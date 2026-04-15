package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var adminPassword = getEnv("ADMIN_PASSWORD", "changeme")
var adminTokenSecret = getEnv("ADMIN_TOKEN_SECRET", "change-this-secret")
var aiAPIURL = getEnv("AI_API_URL", "https://api.openai.com/v1/responses")
var aiAPIKey = getEnv("AI_API_KEY", "your-api-key")
var aiModel = getEnv("AI_MODEL", "gpt-4o")

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	store     *DataStore
	pageTmpls map[string]*template.Template
)

// ============ Security ============

// Rate limiter per IP
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
}

type visitor struct {
	count    int
	lastSeen time.Time
}

var uploadLimiter = &RateLimiter{visitors: make(map[string]*visitor)}
var adminLimiter = &RateLimiter{visitors: make(map[string]*visitor)}

func (rl *RateLimiter) Allow(ip string, maxPerMinute int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]
	if !exists || now.Sub(v.lastSeen) > time.Minute {
		rl.visitors[ip] = &visitor{count: 1, lastSeen: now}
		return true
	}
	v.count++
	v.lastSeen = now
	return v.count <= maxPerMinute
}

// Hash admin token instead of storing raw password in cookie
func hashAdminToken() string {
	h := sha256.Sum256([]byte(adminPassword + adminTokenSecret))
	return hex.EncodeToString(h[:])
}

func isAdmin(r *http.Request) bool {
	cookie, err := r.Cookie("admin_token")
	return err == nil && cookie.Value == hashAdminToken()
}

func setAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    hashAdminToken(),
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// Get real client IP (behind nginx)
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Real-IP"); xff != "" {
		return xff
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// Sanitize nickname: strip anything dangerous
var nicknameCleanRe = regexp.MustCompile(`[<>"';&\x00-\x1f]`)

func sanitizeNickname(s string) string {
	s = strings.TrimSpace(s)
	s = nicknameCleanRe.ReplaceAllString(s, "")
	if len([]rune(s)) > 30 {
		s = string([]rune(s)[:30])
	}
	return s
}

// Validate file magic bytes
func validateFileMagic(data []byte, ext string) bool {
	switch ext {
	case ".pdf":
		return len(data) >= 4 && string(data[:4]) == "%PDF"
	case ".png":
		return len(data) >= 8 && string(data[:4]) == "\x89PNG"
	case ".jpg", ".jpeg":
		return len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8
	case ".docx":
		return len(data) >= 4 && string(data[:2]) == "PK"
	case ".doc":
		return len(data) >= 4 && data[0] == 0xD0 && data[1] == 0xCF
	}
	return false
}

// Security headers middleware
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// Allowed file extensions
var allowedExts = map[string]bool{
	".pdf":  true,
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".docx": true,
	".doc":  true,
}

func isImageFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".jpg" || ext == ".jpeg" || ext == ".png"
}

func isPDFFile(name string) bool {
	return strings.ToLower(filepath.Ext(name)) == ".pdf"
}

func isWordFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".docx" || ext == ".doc"
}

// ============ Data Models ============

type Resume struct {
	ID             int       `json:"id"`
	Nickname       string    `json:"nickname"`
	FileName       string    `json:"file_name"`
	TextContent    string    `json:"text_content"`
	TotalScore     float64   `json:"total_score"`
	IcpcScore      float64   `json:"icpc_score"`
	IcpcComment    string    `json:"icpc_comment"`
	InternScore    float64   `json:"intern_score"`
	InternComment  string    `json:"intern_comment"`
	SchoolScore    float64   `json:"school_score"`
	SchoolComment  string    `json:"school_comment"`
	TechScore      float64   `json:"tech_score"`
	TechComment    string    `json:"tech_comment"`
	ResearchScore   float64   `json:"research_score"`
	ResearchComment string    `json:"research_comment"`
	OverallScore   float64   `json:"overall_score"`
	OverallComment string    `json:"overall_comment"`
	Suggestions    []string  `json:"suggestions"`
	Summary        string    `json:"summary"`
	JobMatches     []JobMatch `json:"job_matches"`
	Status         string    `json:"status"`
	ErrorMsg       string    `json:"error_msg"`
	ShareCode      string    `json:"share_code"`
	Hidden         bool      `json:"hidden"`
	UserID         int       `json:"user_id"` // 0=anonymous
	Likes          int       `json:"likes"`
	CreatedAt      time.Time `json:"created_at"`
}

// FileType returns "image", "pdf", or "word"
func (r *Resume) FileType() string {
	if isImageFile(r.FileName) {
		return "image"
	}
	if isWordFile(r.FileName) {
		return "word"
	}
	return "pdf"
}

type JobMatch struct {
	Title   string `json:"title"`
	Score   int    `json:"score"`
	Reason  string `json:"reason"`
}

type ScoreResult struct {
	TotalScore  float64             `json:"total_score"`
	Dimensions  map[string]DimScore `json:"dimensions"`
	Suggestions []string            `json:"suggestions"`
	Summary     string              `json:"summary"`
	JobMatches  []JobMatch          `json:"job_matches"`
}

type DimScore struct {
	Score   float64 `json:"score"`
	Comment string  `json:"comment"`
}

// ============ User Model ============

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // SHA256 hash
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	UserID    int       `json:"user_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

const sessionSecret = "resume-arena-session-2026"

type Comment struct {
	ID        int       `json:"id"`
	ResumeID  int       `json:"resume_id"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type LikeRecord struct {
	ResumeID int    `json:"resume_id"`
	IP       string `json:"ip"`
}

// ============ JSON File Store ============

type DataStore struct {
	mu            sync.RWMutex
	Resumes       []Resume     `json:"resumes"`
	NextID        int          `json:"next_id"`
	Users         []User       `json:"users"`
	NextUserID    int          `json:"next_user_id"`
	Sessions      []Session    `json:"sessions"`
	Comments      []Comment    `json:"comments"`
	NextCommentID int          `json:"next_comment_id"`
	LikeRecords   []LikeRecord `json:"like_records"`
	path          string
}

func NewDataStore(path string) *DataStore {
	ds := &DataStore{path: path, NextID: 1, NextUserID: 1, NextCommentID: 1}
	data, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(data, ds)
	}
	return ds
}

func (ds *DataStore) save() {
	data, _ := json.MarshalIndent(ds, "", "  ")
	os.WriteFile(ds.path, data, 0644)
}

func (ds *DataStore) Add(r *Resume) int {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	r.ID = ds.NextID
	ds.NextID++
	r.CreatedAt = time.Now()
	ds.Resumes = append(ds.Resumes, *r)
	ds.save()
	return r.ID
}

func (ds *DataStore) GetByShareCode(code string) *Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for i := range ds.Resumes {
		if ds.Resumes[i].ShareCode == code {
			r := ds.Resumes[i]
			return &r
		}
	}
	return nil
}

func (ds *DataStore) GetByID(id int) *Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for i := range ds.Resumes {
		if ds.Resumes[i].ID == id {
			r := ds.Resumes[i]
			return &r
		}
	}
	return nil
}

func (ds *DataStore) Update(id int, fn func(r *Resume)) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i := range ds.Resumes {
		if ds.Resumes[i].ID == id {
			fn(&ds.Resumes[i])
			ds.save()
			return
		}
	}
}

func (ds *DataStore) Delete(id int) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i := range ds.Resumes {
		if ds.Resumes[i].ID == id {
			// Remove uploaded file
			os.Remove(filepath.Join("uploads", ds.Resumes[i].FileName))
			ds.Resumes = append(ds.Resumes[:i], ds.Resumes[i+1:]...)
			ds.save()
			return true
		}
	}
	return false
}

func (ds *DataStore) GetAllResumes() []Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	result := make([]Resume, len(ds.Resumes))
	copy(result, ds.Resumes)
	return result
}

func (ds *DataStore) GetDoneResumes() []Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []Resume
	for _, r := range ds.Resumes {
		if r.Status == "done" {
			result = append(result, r)
		}
	}
	return result
}

func (ds *DataStore) GetPublicDoneResumes() []Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []Resume
	for _, r := range ds.Resumes {
		if r.Status == "done" && !r.Hidden {
			result = append(result, r)
		}
	}
	return result
}

// User methods

func hashPassword(pw string) string {
	h := sha256.Sum256([]byte(pw + sessionSecret))
	return hex.EncodeToString(h[:])
}

func (ds *DataStore) CreateUser(username, password string) (*User, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	// Check duplicate
	for _, u := range ds.Users {
		if u.Username == username {
			return nil, fmt.Errorf("用户名已存在")
		}
	}
	user := User{
		ID:        ds.NextUserID,
		Username:  username,
		Password:  hashPassword(password),
		CreatedAt: time.Now(),
	}
	ds.NextUserID++
	ds.Users = append(ds.Users, user)
	ds.save()
	return &user, nil
}

func (ds *DataStore) AuthUser(username, password string) *User {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	hashed := hashPassword(password)
	for i := range ds.Users {
		if ds.Users[i].Username == username && ds.Users[i].Password == hashed {
			u := ds.Users[i]
			return &u
		}
	}
	return nil
}

func (ds *DataStore) GetUserByID(id int) *User {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for i := range ds.Users {
		if ds.Users[i].ID == id {
			u := ds.Users[i]
			return &u
		}
	}
	return nil
}

func (ds *DataStore) CreateSession(userID int) string {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	token := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d-%d-%s", userID, time.Now().UnixNano(), sessionSecret))))
	ds.Sessions = append(ds.Sessions, Session{
		UserID:    userID,
		Token:     token,
		CreatedAt: time.Now(),
	})
	ds.save()
	return token
}

func (ds *DataStore) GetUserBySession(token string) *User {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	if token == "" {
		return nil
	}
	for _, s := range ds.Sessions {
		if s.Token == token && time.Since(s.CreatedAt) < 7*24*time.Hour {
			for i := range ds.Users {
				if ds.Users[i].ID == s.UserID {
					u := ds.Users[i]
					return &u
				}
			}
		}
	}
	return nil
}

func (ds *DataStore) DeleteSession(token string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i := range ds.Sessions {
		if ds.Sessions[i].Token == token {
			ds.Sessions = append(ds.Sessions[:i], ds.Sessions[i+1:]...)
			ds.save()
			return
		}
	}
}

func (ds *DataStore) GetResumesByUserID(userID int) []Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []Resume
	for _, r := range ds.Resumes {
		if r.UserID == userID {
			result = append(result, r)
		}
	}
	return result
}

// Comment methods

func (ds *DataStore) AddComment(resumeID, userID int, username, content string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.Comments = append(ds.Comments, Comment{
		ID:        ds.NextCommentID,
		ResumeID:  resumeID,
		UserID:    userID,
		Username:  username,
		Content:   sanitizeNickname(content),
		CreatedAt: time.Now(),
	})
	ds.NextCommentID++
	ds.save()
}

func (ds *DataStore) GetComments(resumeID int) []Comment {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []Comment
	for _, c := range ds.Comments {
		if c.ResumeID == resumeID {
			result = append(result, c)
		}
	}
	return result
}

func (ds *DataStore) DeleteComment(commentID int) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i := range ds.Comments {
		if ds.Comments[i].ID == commentID {
			ds.Comments = append(ds.Comments[:i], ds.Comments[i+1:]...)
			ds.save()
			return
		}
	}
}

// Like methods

func (ds *DataStore) AddLike(resumeID int, ip string) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	// Check if already liked
	for _, l := range ds.LikeRecords {
		if l.ResumeID == resumeID && l.IP == ip {
			return false
		}
	}
	ds.LikeRecords = append(ds.LikeRecords, LikeRecord{ResumeID: resumeID, IP: ip})
	for i := range ds.Resumes {
		if ds.Resumes[i].ID == resumeID {
			ds.Resumes[i].Likes++
			break
		}
	}
	ds.save()
	return true
}

func (ds *DataStore) HasLiked(resumeID int, ip string) bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for _, l := range ds.LikeRecords {
		if l.ResumeID == resumeID && l.IP == ip {
			return true
		}
	}
	return false
}

// Week helpers

func getWeekKey(t time.Time) string {
	y, w := t.ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

func (ds *DataStore) GetWeeklyResumes() []Resume {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	currentWeek := getWeekKey(time.Now())
	var result []Resume
	for _, r := range ds.Resumes {
		if r.Status == "done" && getWeekKey(r.CreatedAt) == currentWeek {
			result = append(result, r)
		}
	}
	return result
}

// Stats helpers

func (ds *DataStore) GetStats() map[string]interface{} {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	done := 0
	var totalScore, totalIcpc, totalIntern, totalSchool, totalTech, totalResearch float64
	scoreDist := map[string]int{"90+": 0, "80-89": 0, "70-79": 0, "60-69": 0, "50-59": 0, "<50": 0}
	jobCounts := map[string]int{}

	for _, r := range ds.Resumes {
		if r.Status != "done" {
			continue
		}
		done++
		totalScore += r.TotalScore
		totalIcpc += r.IcpcScore
		totalIntern += r.InternScore
		totalSchool += r.SchoolScore
		totalTech += r.TechScore
		totalResearch += r.ResearchScore

		switch {
		case r.TotalScore >= 90:
			scoreDist["90+"]++
		case r.TotalScore >= 80:
			scoreDist["80-89"]++
		case r.TotalScore >= 70:
			scoreDist["70-79"]++
		case r.TotalScore >= 60:
			scoreDist["60-69"]++
		case r.TotalScore >= 50:
			scoreDist["50-59"]++
		default:
			scoreDist["<50"]++
		}

		for _, jm := range r.JobMatches {
			if jm.Score >= 60 {
				jobCounts[jm.Title]++
			}
		}
	}

	avg := func(v float64) float64 {
		if done == 0 {
			return 0
		}
		return math.Round(v/float64(done)*10) / 10
	}

	// Top 5 job directions
	type jobEntry struct {
		Name  string
		Count int
	}
	var topJobs []jobEntry
	for k, v := range jobCounts {
		topJobs = append(topJobs, jobEntry{k, v})
	}
	sort.Slice(topJobs, func(i, j int) bool { return topJobs[i].Count > topJobs[j].Count })
	if len(topJobs) > 8 {
		topJobs = topJobs[:8]
	}

	return map[string]interface{}{
		"Total":      done,
		"Users":      len(ds.Users),
		"AvgScore":   avg(totalScore),
		"AvgIcpc":    avg(totalIcpc),
		"AvgIntern":  avg(totalIntern),
		"AvgSchool":  avg(totalSchool),
		"AvgTech":     avg(totalTech),
		"AvgResearch": avg(totalResearch),
		"ScoreDist":  scoreDist,
		"TopJobs":    topJobs,
	}
}

// Achievement badges

func getAchievements(r *Resume, rank, total int) []string {
	var badges []string
	if r.TotalScore >= 90 {
		badges = append(badges, "S-Tier")
	}
	if r.IcpcScore >= 88 {
		badges = append(badges, "ICPC Legend")
	} else if r.IcpcScore >= 78 {
		badges = append(badges, "ICPC Master")
	} else if r.IcpcScore >= 65 {
		badges = append(badges, "ICPC Pro")
	}
	if r.InternScore >= 88 {
		badges = append(badges, "Big Tech Star")
	}
	if r.TechScore >= 85 {
		badges = append(badges, "Tech Guru")
	}
	if r.SchoolScore >= 90 {
		badges = append(badges, "Top School")
	}
	if total > 0 && rank <= total/10+1 {
		badges = append(badges, "Top 10%")
	}
	if rank == 1 {
		badges = append(badges, "Champion")
	} else if rank <= 3 {
		badges = append(badges, "Podium")
	}
	if r.OverallScore >= 80 {
		badges = append(badges, "Resume Expert")
	}
	return badges
}

func getCurrentUser(r *http.Request) *User {
	cookie, err := r.Cookie("user_session")
	if err != nil {
		return nil
	}
	return store.GetUserBySession(cookie.Value)
}

// render helper: auto-injects CurrentUser into template data
func render(w http.ResponseWriter, r *http.Request, page string, data map[string]interface{}) {
	if data == nil {
		data = map[string]interface{}{}
	}
	data["CurrentUser"] = getCurrentUser(r)
	pageTmpls[page].ExecuteTemplate(w, "base", data)
}

// ============ Main ============

func main() {
	store = NewDataStore("data.json")
	loadSchoolScores()
	loadPrompt()
	initTemplates()
	os.MkdirAll("uploads", 0755)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/register", handleRegister)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/profile", handleProfile)
	mux.HandleFunc("/result/", handleResult)
	mux.HandleFunc("/ranking", handleRanking)
	mux.HandleFunc("/board/", handleBoard)
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/api/status/", handleStatus)
	mux.HandleFunc("/api/like/", handleLike)
	mux.HandleFunc("/api/comment/", handleComment)
	mux.HandleFunc("/file/", handleFile)
	mux.HandleFunc("/prompt", handlePrompt)
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/admin/delete/", handleAdminDelete)
	mux.HandleFunc("/admin/rename/", handleAdminRename)
	mux.HandleFunc("/admin/toggle-hidden/", handleAdminToggleHidden)
	mux.HandleFunc("/admin/rescore-all", handleAdminRescoreAll)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Resume Arena starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, securityMiddleware(mux)))
}

func initTemplates() {
	funcMap := template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"rankClass": func(i int) string {
			switch i {
			case 1:
				return "gold"
			case 2:
				return "silver"
			case 3:
				return "bronze"
			default:
				return ""
			}
		},
		"fileIcon": func(name string) string {
			if isImageFile(name) {
				return "bi-file-earmark-image"
			}
			if isWordFile(name) {
				return "bi-file-earmark-word"
			}
			return "bi-file-earmark-pdf"
		},
		"isImage": func(name string) bool {
			return isImageFile(name)
		},
		"timeFormat": func(t time.Time) string {
			return t.Format("2006-01-02 15:04")
		},
	}

	pages := []string{"index", "upload", "result", "ranking", "admin", "prompt", "login", "profile", "board", "stats"}
	pageTmpls = make(map[string]*template.Template)
	for _, p := range pages {
		pageTmpls[p] = template.Must(
			template.New("").Funcs(funcMap).ParseFiles(
				"templates/base.html",
				"templates/"+p+".html",
			),
		)
	}
}

// ============ Handlers ============

type RankEntry struct {
	Rank          int
	Nickname      string
	TotalScore    float64
	IcpcScore     float64
	InternScore   float64
	SchoolScore   float64
	TechScore     float64
	ResearchScore float64
	ShareCode     string
	FileName      string
	Hidden        bool
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	done := store.GetDoneResumes()
	sort.Slice(done, func(i, j int) bool {
		return done[i].TotalScore > done[j].TotalScore
	})

	if len(done) > 5 {
		done = done[:5]
	}

	top := make([]RankEntry, len(done))
	for i, d := range done {
		top[i] = RankEntry{
			Rank:        i + 1,
			Nickname:    d.Nickname,
			TotalScore:  d.TotalScore,
			IcpcScore:   d.IcpcScore,
			InternScore: d.InternScore,
			SchoolScore: d.SchoolScore,
			TechScore:     d.TechScore,
			ResearchScore: d.ResearchScore,
			ShareCode:     d.ShareCode,
			FileName:      d.FileName,
			Hidden:        d.Hidden,
		}
	}

	allDone := store.GetDoneResumes()
	render(w, r, "index", map[string]interface{}{
		"Top":   top,
		"Total": len(allDone),
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, r, "upload", map[string]interface{}{})
		return
	}

	// Rate limit: max 5 uploads per minute per IP
	ip := getClientIP(r)
	if !uploadLimiter.Allow(ip, 5) {
		render(w, r, "upload", map[string]interface{}{
			"Error": "上传太频繁，请稍后再试",
		})
		return
	}

	r.ParseMultipartForm(10 << 20)

	nickname := sanitizeNickname(r.FormValue("nickname"))
	if nickname == "" {
		render(w, r, "upload", map[string]interface{}{
			"Error": "请输入昵称",
		})
		return
	}

	file, header, err := r.FormFile("resume")
	if err != nil {
		render(w, r, "upload", map[string]interface{}{
			"Error": "请上传简历文件",
		})
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExts[ext] {
		render(w, r, "upload", map[string]interface{}{
			"Error": "不支持的文件格式，请上传 PDF、图片(JPG/PNG) 或 Word(DOCX) 文件",
		})
		return
	}

	if header.Size > 10<<20 {
		render(w, r, "upload", map[string]interface{}{
			"Error": "文件大小不能超过10MB",
		})
		return
	}

	// Read file content for magic byte validation
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		render(w, r, "upload", map[string]interface{}{
			"Error": "文件读取失败",
		})
		return
	}

	// Validate file magic bytes (prevent disguised files)
	if !validateFileMagic(fileBytes, ext) {
		log.Printf("[SECURITY] Invalid file magic from IP %s: claimed %s but magic mismatch", ip, ext)
		render(w, r, "upload", map[string]interface{}{
			"Error": "文件内容与格式不匹配，请上传真实的简历文件",
		})
		return
	}

	shareCode := fmt.Sprintf("%d", time.Now().UnixNano()%10000000000)
	hidden := r.FormValue("hidden") == "on"

	fileName := shareCode + ext
	savePath := filepath.Join("uploads", fileName)
	if err = os.WriteFile(savePath, fileBytes, 0644); err != nil {
		http.Error(w, "文件保存失败", 500)
		return
	}

	userID := 0
	if user := getCurrentUser(r); user != nil {
		userID = user.ID
	}

	resume := &Resume{
		Nickname:  nickname,
		FileName:  fileName,
		ShareCode: shareCode,
		Hidden:    hidden,
		UserID:    userID,
		Status:    "pending",
	}
	id := store.Add(resume)

	go scoreResume(id, savePath)

	http.Redirect(w, r, fmt.Sprintf("/result/%s", shareCode), http.StatusSeeOther)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/result/")
	if code == "" {
		http.NotFound(w, r)
		return
	}

	resume := store.GetByShareCode(code)
	if resume == nil {
		http.NotFound(w, r)
		return
	}

	rank := 0
	if resume.Status == "done" {
		done := store.GetDoneResumes()
		for _, d := range done {
			if d.TotalScore > resume.TotalScore {
				rank++
			}
		}
		rank++
	}

	total := len(store.GetDoneResumes())
	badges := getAchievements(resume, rank, total)
	comments := store.GetComments(resume.ID)
	hasLiked := store.HasLiked(resume.ID, getClientIP(r))

	// Anonymized comments for hidden resumes
	anonIcpc := anonIcpcComment(resume.IcpcScore)
	anonSchool := anonSchoolComment(resume.SchoolScore)
	anonResearch := anonResearchComment(resume.ResearchScore)

	render(w, r, "result", map[string]interface{}{
		"Resume":       resume,
		"Rank":         rank,
		"Total":        total,
		"Badges":       badges,
		"Comments":     comments,
		"HasLiked":     hasLiked,
		"AnonIcpc":     anonIcpc,
		"AnonSchool":   anonSchool,
		"AnonResearch": anonResearch,
		"Scores": []float64{
			resume.IcpcScore, resume.InternScore,
			resume.SchoolScore, resume.TechScore, resume.ResearchScore, resume.OverallScore,
		},
	})
}

func handleRanking(w http.ResponseWriter, r *http.Request) {
	sortBy := r.URL.Query().Get("sort")
	done := store.GetDoneResumes()

	switch sortBy {
	case "icpc":
		sort.Slice(done, func(i, j int) bool { return done[i].IcpcScore > done[j].IcpcScore })
	case "intern":
		sort.Slice(done, func(i, j int) bool { return done[i].InternScore > done[j].InternScore })
	case "school":
		sort.Slice(done, func(i, j int) bool { return done[i].SchoolScore > done[j].SchoolScore })
	case "tech":
		sort.Slice(done, func(i, j int) bool { return done[i].TechScore > done[j].TechScore })
	case "research":
		sort.Slice(done, func(i, j int) bool { return done[i].ResearchScore > done[j].ResearchScore })
	default:
		sortBy = "total"
		sort.Slice(done, func(i, j int) bool { return done[i].TotalScore > done[j].TotalScore })
	}

	entries := make([]RankEntry, len(done))
	for i, d := range done {
		entries[i] = RankEntry{
			Rank:        i + 1,
			Nickname:    d.Nickname,
			TotalScore:  d.TotalScore,
			IcpcScore:   d.IcpcScore,
			InternScore: d.InternScore,
			SchoolScore: d.SchoolScore,
			TechScore:     d.TechScore,
			ResearchScore: d.ResearchScore,
			ShareCode:     d.ShareCode,
			FileName:      d.FileName,
			Hidden:        d.Hidden,
		}
	}

	render(w, r, "ranking", map[string]interface{}{
		"Entries": entries,
		"SortBy":  sortBy,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/api/status/")
	resume := store.GetByShareCode(code)
	if resume == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": resume.Status,
		"error":  resume.ErrorMsg,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if getCurrentUser(r) != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	if r.Method == "GET" {
		render(w, r, "login", map[string]interface{}{"Tab": "login"})
		return
	}
	ip := getClientIP(r)
	if !adminLimiter.Allow(ip, 10) {
		render(w, r, "login", map[string]interface{}{
			"Tab": "login", "LoginError": "尝试太频繁，请稍后再试",
		})
		return
	}
	r.ParseForm()
	username := sanitizeNickname(r.FormValue("username"))
	password := r.FormValue("password")

	user := store.AuthUser(username, password)
	if user == nil {
		render(w, r, "login", map[string]interface{}{
			"Tab": "login", "LoginError": "用户名或密码错误",
		})
		return
	}

	token := store.CreateSession(user.ID)
	http.SetCookie(w, &http.Cookie{
		Name: "user_session", Value: token, Path: "/",
		MaxAge: 7 * 86400, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if getCurrentUser(r) != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	if r.Method != "POST" {
		render(w, r, "login", map[string]interface{}{"Tab": "register"})
		return
	}
	ip := getClientIP(r)
	if !adminLimiter.Allow(ip, 5) {
		render(w, r, "login", map[string]interface{}{
			"Tab": "register", "RegError": "操作太频繁，请稍后再试",
		})
		return
	}
	r.ParseForm()
	username := sanitizeNickname(r.FormValue("username"))
	password := r.FormValue("password")
	password2 := r.FormValue("password2")

	if len(username) < 2 || len(username) > 20 {
		render(w, r, "login", map[string]interface{}{
			"Tab": "register", "RegError": "用户名长度需要2-20个字符",
		})
		return
	}
	if len(password) < 6 {
		render(w, r, "login", map[string]interface{}{
			"Tab": "register", "RegError": "密码至少6个字符",
		})
		return
	}
	if password != password2 {
		render(w, r, "login", map[string]interface{}{
			"Tab": "register", "RegError": "两次密码不一致",
		})
		return
	}

	user, err := store.CreateUser(username, password)
	if err != nil {
		render(w, r, "login", map[string]interface{}{
			"Tab": "register", "RegError": err.Error(),
		})
		return
	}

	token := store.CreateSession(user.ID)
	http.SetCookie(w, &http.Cookie{
		Name: "user_session", Value: token, Path: "/",
		MaxAge: 7 * 86400, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_session")
	if err == nil {
		store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "user_session", Value: "", Path: "/", MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	resumes := store.GetResumesByUserID(user.ID)
	sort.Slice(resumes, func(i, j int) bool {
		return resumes[i].CreatedAt.After(resumes[j].CreatedAt)
	})

	render(w, r, "profile", map[string]interface{}{
		"User":    user,
		"Resumes": resumes,
		"Count":   len(resumes),
	})
}

func handleBoard(w http.ResponseWriter, r *http.Request) {
	boardType := strings.TrimPrefix(r.URL.Path, "/board/")
	if boardType == "" {
		boardType = "icpc"
	}

	boards := map[string]struct {
		Title   string
		SortFn  func(a, b Resume) bool
		ScoreFn func(r Resume) float64
	}{
		"icpc": {
			"ICPC/CCPC 竞赛榜",
			func(a, b Resume) bool { return a.IcpcScore > b.IcpcScore },
			func(r Resume) float64 { return r.IcpcScore },
		},
		"intern": {
			"实习/项目榜",
			func(a, b Resume) bool { return a.InternScore > b.InternScore },
			func(r Resume) float64 { return r.InternScore },
		},
		"school": {
			"学校背景榜",
			func(a, b Resume) bool { return a.SchoolScore > b.SchoolScore },
			func(r Resume) float64 { return r.SchoolScore },
		},
		"tech": {
			"技术栈榜",
			func(a, b Resume) bool { return a.TechScore > b.TechScore },
			func(r Resume) float64 { return r.TechScore },
		},
		"research": {
			"科研/论文榜",
			func(a, b Resume) bool { return a.ResearchScore > b.ResearchScore },
			func(r Resume) float64 { return r.ResearchScore },
		},
	}

	board, ok := boards[boardType]
	if !ok {
		http.Redirect(w, r, "/board/icpc", http.StatusSeeOther)
		return
	}

	done := store.GetDoneResumes()
	sort.Slice(done, func(i, j int) bool { return board.SortFn(done[i], done[j]) })
	if len(done) > 50 {
		done = done[:50]
	}

	type BoardEntry struct {
		Rank       int
		Nickname   string
		MainScore  float64
		TotalScore float64
		ShareCode  string
		Hidden     bool
		FileName   string
	}
	entries := make([]BoardEntry, len(done))
	for i, d := range done {
		entries[i] = BoardEntry{
			Rank:       i + 1,
			Nickname:   d.Nickname,
			MainScore:  board.ScoreFn(d),
			TotalScore: d.TotalScore,
			ShareCode:  d.ShareCode,
			Hidden:     d.Hidden,
			FileName:   d.FileName,
		}
	}

	render(w, r, "board", map[string]interface{}{
		"Entries":   entries,
		"BoardType": boardType,
		"Title":     board.Title,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	stats := store.GetStats()
	render(w, r, "stats", stats)
}

func handleLike(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/api/like/")
	resume := store.GetByShareCode(code)
	if resume == nil {
		http.Error(w, "not found", 404)
		return
	}
	ip := getClientIP(r)
	ok := store.AddLike(resume.ID, ip)
	w.Header().Set("Content-Type", "application/json")
	likes := resume.Likes
	if ok {
		likes++
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": ok, "likes": likes})
}

func handleComment(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/api/comment/")
	resume := store.GetByShareCode(code)
	if resume == nil {
		http.Error(w, "not found", 404)
		return
	}

	if r.Method == "POST" {
		user := getCurrentUser(r)
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "请先登录"})
			return
		}
		ip := getClientIP(r)
		if !uploadLimiter.Allow(ip, 10) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "评论太频繁"})
			return
		}
		r.ParseForm()
		content := strings.TrimSpace(r.FormValue("content"))
		if len(content) < 1 || len([]rune(content)) > 200 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "评论长度1-200字"})
			return
		}
		store.AddComment(resume.ID, user.ID, user.Username, content)
	}

	comments := store.GetComments(resume.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

func handlePrompt(w http.ResponseWriter, r *http.Request) {
	render(w, r, "prompt", map[string]interface{}{
		"Prompt": scoringPrompt,
	})
}

// handleFile serves uploaded resume files for preview
func handleFile(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/file/")
	if code == "" {
		http.NotFound(w, r)
		return
	}

	resume := store.GetByShareCode(code)
	if resume == nil {
		http.NotFound(w, r)
		return
	}

	// Hidden resumes: only admin can view the file
	if resume.Hidden && !isAdmin(r) {
		http.Error(w, "该简历已设为私密", 403)
		return
	}

	filePath := filepath.Join("uploads", resume.FileName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	// Set appropriate content type
	ext := strings.ToLower(filepath.Ext(resume.FileName))
	switch ext {
	case ".pdf":
		w.Header().Set("Content-Type", "application/pdf")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".docx":
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	case ".doc":
		w.Header().Set("Content-Type", "application/msword")
	}

	// Prevent XSS via uploaded files (especially PDF with embedded JS)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Use anonymous filename to protect privacy
	anonName := fmt.Sprintf("resume_%s%s", resume.ShareCode, ext)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, anonName))
	http.ServeFile(w, r, filePath)
}

// ============ Admin ============

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	isAuthed := isAdmin(r)

	if r.Method == "POST" && !isAuthed {
		// Rate limit admin login: max 5 attempts per minute per IP
		ip := getClientIP(r)
		if !adminLimiter.Allow(ip, 5) {
			render(w, r, "admin", map[string]interface{}{
				"NeedLogin": true,
				"Error":     "登录尝试太频繁，请稍后再试",
			})
			return
		}

		r.ParseForm()
		pwd := r.FormValue("password")
		if pwd == adminPassword {
			setAdminCookie(w)
			isAuthed = true
		} else {
			log.Printf("[SECURITY] Failed admin login from IP %s", ip)
			render(w, r, "admin", map[string]interface{}{
				"NeedLogin": true,
				"Error":     "密码错误",
			})
			return
		}
	}

	if !isAuthed {
		render(w, r, "admin", map[string]interface{}{
			"NeedLogin": true,
		})
		return
	}

	all := store.GetAllResumes()
	// Sort by newest first
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})

	render(w, r, "admin", map[string]interface{}{
		"Authed":  true,
		"Resumes": all,
		"Total":   len(all),
	})
}

func handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Error(w, "Unauthorized", 403)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/delete/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	if id > 0 {
		store.Delete(id)
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAdminRename(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Error(w, "Unauthorized", 403)
		return
	}

	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rename/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	r.ParseForm()
	newName := sanitizeNickname(r.FormValue("nickname"))
	if id > 0 && newName != "" {
		store.Update(id, func(resume *Resume) {
			resume.Nickname = newName
		})
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAdminToggleHidden(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Error(w, "Unauthorized", 403)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/toggle-hidden/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	if id > 0 {
		store.Update(id, func(resume *Resume) {
			resume.Hidden = !resume.Hidden
		})
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAdminRescoreAll(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Error(w, "Unauthorized", 403)
		return
	}

	all := store.GetAllResumes()
	count := 0
	for _, resume := range all {
		if resume.Status == "done" || resume.Status == "error" {
			filePath := filepath.Join("uploads", resume.FileName)
			if _, err := os.Stat(filePath); err == nil {
				count++
				id := resume.ID
				fp := filePath
				go scoreResume(id, fp)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": fmt.Sprintf("已开始重新评分 %d 份简历", count),
	})
}

// ============ Scoring ============

func scoreResume(id int, filePath string) {
	store.Update(id, func(r *Resume) { r.Status = "scoring" })

	var result *ScoreResult
	var err error

	if isImageFile(filePath) {
		// Use multimodal API for images
		result, err = callAIScoringImage(filePath)
	} else {
		// Extract text first (PDF or Word)
		var text string
		if isWordFile(filePath) {
			text, err = extractDocxText(filePath)
		} else {
			text, err = extractPDFText(filePath)
		}

		if err != nil {
			store.Update(id, func(r *Resume) {
				r.Status = "error"
				r.ErrorMsg = fmt.Sprintf("文件解析失败: %v", err)
			})
			return
		}

		if strings.TrimSpace(text) == "" {
			store.Update(id, func(r *Resume) {
				r.Status = "error"
				r.ErrorMsg = "无法从文件中提取文本内容，请确保文件包含可读的文字"
			})
			return
		}

		store.Update(id, func(r *Resume) { r.TextContent = text })
		result, err = callAIScoringText(text)
	}

	if err != nil {
		store.Update(id, func(r *Resume) {
			r.Status = "error"
			r.ErrorMsg = fmt.Sprintf("AI评分失败: %v", err)
		})
		return
	}

	store.Update(id, func(r *Resume) {
		icpc := result.Dimensions["icpc_ccpc"]
		intern := result.Dimensions["internship_project"]
		school := result.Dimensions["school"]
		tech := result.Dimensions["tech_stack"]
		research := result.Dimensions["research"]
		overall := result.Dimensions["overall"]

		// Override school score with hardcoded mapping if found
		schoolScore := overrideSchoolScore(school.Score, school.Comment)

		// New weights: ICPC 25%, Intern 20%, School 15%, Tech 15%, Research 15%, Overall 10%
		r.TotalScore = math.Round((icpc.Score*0.25+intern.Score*0.20+schoolScore*0.15+tech.Score*0.15+research.Score*0.15+overall.Score*0.10)*10) / 10
		r.IcpcScore = icpc.Score
		r.IcpcComment = icpc.Comment
		r.InternScore = intern.Score
		r.InternComment = intern.Comment
		r.SchoolScore = schoolScore
		r.SchoolComment = school.Comment
		r.TechScore = tech.Score
		r.TechComment = tech.Comment
		r.ResearchScore = research.Score
		r.ResearchComment = research.Comment
		r.OverallScore = overall.Score
		r.OverallComment = overall.Comment
		r.Suggestions = result.Suggestions
		r.Summary = result.Summary
		r.JobMatches = result.JobMatches
		r.Status = "done"
	})
}

// ============ File Extraction ============

func extractPDFText(pdfPath string) (string, error) {
	cmd := exec.Command("pdftotext", pdfPath, "-")
	out, err := cmd.Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return string(out), nil
	}
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return "", err
	}
	return extractTextFromPDFBytes(data), nil
}

func extractTextFromPDFBytes(data []byte) string {
	content := string(data)
	var texts []string
	inParen := false
	var current strings.Builder
	escape := false
	for _, ch := range content {
		if escape {
			current.WriteRune(ch)
			escape = false
			continue
		}
		if ch == '\\' && inParen {
			escape = true
			continue
		}
		if ch == '(' {
			inParen = true
			continue
		}
		if ch == ')' && inParen {
			inParen = false
			t := current.String()
			if len(t) > 1 {
				texts = append(texts, t)
			}
			current.Reset()
			continue
		}
		if inParen && ch >= 32 && ch < 127 {
			current.WriteRune(ch)
		}
	}
	return strings.Join(texts, " ")
}

func extractDocxText(docxPath string) (string, error) {
	r, err := zip.OpenReader(docxPath)
	if err != nil {
		return "", fmt.Errorf("无法打开Word文件: %v", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			defer rc.Close()
			return parseDocXML(rc)
		}
	}
	return "", fmt.Errorf("无法在Word文件中找到文档内容")
}

func parseDocXML(r io.Reader) (string, error) {
	decoder := xml.NewDecoder(r)
	var texts []string
	var inText bool

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "t" {
				inText = true
			}
		case xml.EndElement:
			if t.Name.Local == "t" {
				inText = false
			}
			if t.Name.Local == "p" {
				texts = append(texts, "\n")
			}
		case xml.CharData:
			if inText {
				texts = append(texts, string(t))
			}
		}
	}
	return strings.Join(texts, ""), nil
}

// ============ AI Scoring ============

var scoringPrompt string

// School score mapping
var schoolScores map[string]float64

func loadSchoolScores() {
	data, err := os.ReadFile("schools.json")
	if err != nil {
		log.Printf("Warning: schools.json not found, using AI scores only")
		return
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)

	schoolScores = make(map[string]float64)
	for _, v := range raw {
		var group map[string]interface{}
		if json.Unmarshal(v, &group) == nil {
			for name, score := range group {
				if strings.HasPrefix(name, "_") {
					continue
				}
				if s, ok := score.(float64); ok {
					schoolScores[strings.ToLower(name)] = s
				}
			}
		}
	}
	log.Printf("Loaded %d school score mappings", len(schoolScores))
}

// sortedSchoolNames is sorted by length DESC for longest-match-first
var sortedSchoolNames []string

func buildSortedSchoolNames() {
	for name := range schoolScores {
		sortedSchoolNames = append(sortedSchoolNames, name)
	}
	sort.Slice(sortedSchoolNames, func(i, j int) bool {
		return len(sortedSchoolNames[i]) > len(sortedSchoolNames[j])
	})
}

func overrideSchoolScore(aiScore float64, comment string) float64 {
	if schoolScores == nil {
		return aiScore
	}
	if sortedSchoolNames == nil {
		buildSortedSchoolNames()
	}
	commentLower := strings.ToLower(comment)
	// Longest match first - prevents "浙大" matching "浙大宁波理工学院"
	for _, name := range sortedSchoolNames {
		if strings.Contains(commentLower, name) {
			return schoolScores[name]
		}
	}
	return aiScore
}

// Generate anonymized comments for hidden resumes
func anonIcpcComment(score float64) string {
	switch {
	case score >= 95:
		return "WF/IOI金牌级别选手"
	case score >= 88:
		return "WF/EC Final级别选手"
	case score >= 78:
		return "区域赛金牌级别选手"
	case score >= 65:
		return "区域赛银牌级别选手"
	case score >= 52:
		return "区域赛铜牌级别选手"
	case score >= 40:
		return "有区域赛参赛经历"
	case score >= 25:
		return "有非核心赛事获奖经历"
	case score >= 10:
		return "有少量竞赛相关经历"
	default:
		return "简历中未提及竞赛经历"
	}
}

func anonSchoolComment(score float64) string {
	switch {
	case score >= 93:
		return "C9/顶尖高校"
	case score >= 85:
		return "强985/顶尖211高校"
	case score >= 75:
		return "985高校"
	case score >= 65:
		return "211高校"
	case score >= 55:
		return "普通一本高校"
	case score >= 35:
		return "二本/三本高校"
	case score >= 25:
		return "简历中未提及学校信息"
	default:
		return "简历中未提及学校信息"
	}
}

func anonResearchComment(score float64) string {
	switch {
	case score >= 85:
		return "有顶会论文发表经历"
	case score >= 65:
		return "有较高质量科研论文"
	case score >= 40:
		return "有科研/论文经历"
	case score >= 20:
		return "有少量科研经历"
	default:
		return "简历中未提及科研经历"
	}
}

func loadPrompt() {
	data, err := os.ReadFile("prompt.txt")
	if err != nil {
		log.Fatalf("Failed to load prompt.txt: %v", err)
	}
	scoringPrompt = string(data)
	log.Printf("Loaded prompt.txt (%d bytes)", len(scoringPrompt))
}

func callAIScoringText(resumeText string) (*ScoreResult, error) {
	if len(resumeText) > 8000 {
		resumeText = resumeText[:8000]
	}

	prompt := scoringPrompt + "\n\n简历内容：\n" + resumeText

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model": aiModel,
		"input": prompt,
	})

	return doAIRequest(reqBody)
}

func callAIScoringImage(imagePath string) (*ScoreResult, error) {
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, fmt.Errorf("读取图片失败: %v", err)
	}

	ext := strings.ToLower(filepath.Ext(imagePath))
	mimeType := "image/jpeg"
	if ext == ".png" {
		mimeType = "image/png"
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	dataURL := fmt.Sprintf("data:%s;base64,%s", mimeType, b64)

	prompt := scoringPrompt + "\n\n请仔细查看这份简历图片，提取其中的所有信息后进行评分。"

	// Multimodal input format for /v1/responses
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model": aiModel,
		"input": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{"type": "input_text", "text": prompt},
					{"type": "input_image", "image_url": dataURL},
				},
			},
		},
	})

	return doAIRequest(reqBody)
}

func doAIRequest(reqBody []byte) (*ScoreResult, error) {
	req, err := http.NewRequest("POST", aiAPIURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer " + aiAPIKey)

	client := &http.Client{Timeout: 180 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API返回状态码 %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Output []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("解析API响应失败: %v", err)
	}

	if len(apiResp.Output) == 0 || len(apiResp.Output[0].Content) == 0 {
		return nil, fmt.Errorf("API返回空响应")
	}

	aiText := apiResp.Output[0].Content[0].Text

	start := strings.Index(aiText, "{")
	end := strings.LastIndex(aiText, "}")
	if start >= 0 && end > start {
		aiText = aiText[start : end+1]
	}

	var result ScoreResult
	if err := json.Unmarshal([]byte(aiText), &result); err != nil {
		return nil, fmt.Errorf("解析评分结果失败: %v\n原文: %s", err, aiText)
	}

	return &result, nil
}
