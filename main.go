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
	OverallScore   float64   `json:"overall_score"`
	OverallComment string    `json:"overall_comment"`
	Suggestions    []string  `json:"suggestions"`
	Summary        string    `json:"summary"`
	JobMatches     []JobMatch `json:"job_matches"`
	Status         string    `json:"status"`
	ErrorMsg       string    `json:"error_msg"`
	ShareCode      string    `json:"share_code"`
	Hidden         bool      `json:"hidden"`
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

// ============ JSON File Store ============

type DataStore struct {
	mu      sync.RWMutex
	Resumes []Resume `json:"resumes"`
	NextID  int      `json:"next_id"`
	path    string
}

func NewDataStore(path string) *DataStore {
	ds := &DataStore{path: path, NextID: 1}
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

// ============ Main ============

func main() {
	store = NewDataStore("data.json")
	loadPrompt()
	initTemplates()
	os.MkdirAll("uploads", 0755)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/result/", handleResult)
	mux.HandleFunc("/ranking", handleRanking)
	mux.HandleFunc("/api/status/", handleStatus)
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

	pages := []string{"index", "upload", "result", "ranking", "admin", "prompt"}
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
	Rank        int
	Nickname    string
	TotalScore  float64
	IcpcScore   float64
	InternScore float64
	SchoolScore float64
	TechScore   float64
	ShareCode   string
	FileName    string
	Hidden      bool
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
			TechScore:   d.TechScore,
			ShareCode:   d.ShareCode,
			FileName:    d.FileName,
			Hidden:      d.Hidden,
		}
	}

	allDone := store.GetDoneResumes()
	pageTmpls["index"].ExecuteTemplate(w, "base", map[string]interface{}{
		"Top":   top,
		"Total": len(allDone),
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{})
		return
	}

	// Rate limit: max 5 uploads per minute per IP
	ip := getClientIP(r)
	if !uploadLimiter.Allow(ip, 5) {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
			"Error": "上传太频繁，请稍后再试",
		})
		return
	}

	r.ParseMultipartForm(10 << 20)

	nickname := sanitizeNickname(r.FormValue("nickname"))
	if nickname == "" {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
			"Error": "请输入昵称",
		})
		return
	}

	file, header, err := r.FormFile("resume")
	if err != nil {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
			"Error": "请上传简历文件",
		})
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExts[ext] {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
			"Error": "不支持的文件格式，请上传 PDF、图片(JPG/PNG) 或 Word(DOCX) 文件",
		})
		return
	}

	if header.Size > 10<<20 {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
			"Error": "文件大小不能超过10MB",
		})
		return
	}

	// Read file content for magic byte validation
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
			"Error": "文件读取失败",
		})
		return
	}

	// Validate file magic bytes (prevent disguised files)
	if !validateFileMagic(fileBytes, ext) {
		log.Printf("[SECURITY] Invalid file magic from IP %s: claimed %s but magic mismatch", ip, ext)
		pageTmpls["upload"].ExecuteTemplate(w, "base", map[string]interface{}{
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

	resume := &Resume{
		Nickname:  nickname,
		FileName:  fileName,
		ShareCode: shareCode,
		Hidden:    hidden,
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

	pageTmpls["result"].ExecuteTemplate(w, "base", map[string]interface{}{
		"Resume": resume,
		"Rank":   rank,
		"Total":  len(store.GetDoneResumes()),
		"Scores": []float64{
			resume.IcpcScore, resume.InternScore,
			resume.SchoolScore, resume.TechScore, resume.OverallScore,
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
			TechScore:   d.TechScore,
			ShareCode:   d.ShareCode,
			FileName:    d.FileName,
			Hidden:      d.Hidden,
		}
	}

	pageTmpls["ranking"].ExecuteTemplate(w, "base", map[string]interface{}{
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

func handlePrompt(w http.ResponseWriter, r *http.Request) {
	pageTmpls["prompt"].ExecuteTemplate(w, "base", map[string]interface{}{
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
			pageTmpls["admin"].ExecuteTemplate(w, "base", map[string]interface{}{
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
			pageTmpls["admin"].ExecuteTemplate(w, "base", map[string]interface{}{
				"NeedLogin": true,
				"Error":     "密码错误",
			})
			return
		}
	}

	if !isAuthed {
		pageTmpls["admin"].ExecuteTemplate(w, "base", map[string]interface{}{
			"NeedLogin": true,
		})
		return
	}

	all := store.GetAllResumes()
	// Sort by newest first
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})

	pageTmpls["admin"].ExecuteTemplate(w, "base", map[string]interface{}{
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
		overall := result.Dimensions["overall"]

		// Calculate total score ourselves - don't trust AI's math
		r.TotalScore = math.Round((icpc.Score*0.3+intern.Score*0.25+school.Score*0.2+tech.Score*0.15+overall.Score*0.1)*10) / 10
		r.IcpcScore = icpc.Score
		r.IcpcComment = icpc.Comment
		r.InternScore = intern.Score
		r.InternComment = intern.Comment
		r.SchoolScore = school.Score
		r.SchoolComment = school.Comment
		r.TechScore = tech.Score
		r.TechComment = tech.Comment
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
