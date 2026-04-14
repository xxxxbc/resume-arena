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

var scoringPrompt = `你是一位严格的ACM/ICPC竞赛圈简历评审专家。请基于简历中**实际写出的内容**进行评分，严禁脑补或推测简历中没有提到的信息。

核心原则：
- **只评价简历里写了的东西**。没写到的维度一律给低分，不要因为其他维度好就脑补。
- **信息量少 = 低分**。一份只写了三四行的简历，即使提到的内容质量高，总分也不应超过60分。
- **严格按证据打分**。

重要：你必须且只能返回有效的JSON，不要包含任何其他文字。JSON格式如下：
{
  "total_score": <0-100的数字>,
  "dimensions": {
    "icpc_ccpc": {"score": <0-100>, "comment": "<评价>"},
    "internship_project": {"score": <0-100>, "comment": "<评价>"},
    "school": {"score": <0-100>, "comment": "<评价>"},
    "tech_stack": {"score": <0-100>, "comment": "<评价>"},
    "overall": {"score": <0-100>, "comment": "<评价>"}
  },
  "suggestions": ["<建议1>", "<建议2>", "<建议3>"],
  "summary": "<2-3句话的总体评价>",
  "job_matches": [
    {"title": "<岗位名称>", "score": <匹配度0-100>, "reason": "<一句话说明匹配原因>"},
    {"title": "<岗位名称>", "score": <匹配度0-100>, "reason": "<一句话说明匹配原因>"},
    {"title": "<岗位名称>", "score": <匹配度0-100>, "reason": "<一句话说明匹配原因>"}
  ]
}

各维度评分标准（严格按以下标准打分）：

1. icpc_ccpc (竞赛实力, 权重30%):
   这个维度只看**正式算法竞赛成绩**。注意：顶端要留给WF和EC Final，整体不要打太高。

   **SS级（95-100分）—— 传奇级：**
   - ICPC World Finals 金牌/银牌
   - IOI金牌

   **S级（88-94分）—— 顶尖选手：**
   - ICPC World Finals 铜牌/参赛（能去WF本身就很强）
   - ICPC EC Final（亚洲东大陆决赛）金牌/银牌
   - IOI银牌铜牌、NOI金牌

   **A+级（78-87分）—— 一流选手：**
   - ICPC EC Final 铜牌/参赛
   - ICPC区域赛金牌（注意：区域赛金牌很强但低于EC Final）
   - CCPC全国决赛金银牌
   - NOI银牌铜牌、省选/省队选手
   - 多次区域赛银牌

   **A级（65-77分）—— 强队选手：**
   - ICPC/CCPC区域赛银牌（65-72分）
   - CCPC全国决赛铜牌
   - CCPC全国邀请赛（注意：邀请赛≠全国总决赛，含金量低于区域赛）金牌（60-67分）
   - 如果同时有区域赛银牌+邀请赛金牌，应取较高成绩+适当加分（72-77分）
   - **评分规则：多个奖项组合 > 单个奖项。例如：区域赛银+邀请赛金 > 单个区域赛银 > 单个邀请赛金**

   **B+级（52-64分）—— 中上水平：**
   - ICPC/CCPC区域赛铜牌（55-64分）
   - CCPC全国邀请赛银牌/铜牌（52-60分）
   - 各省大学生程序设计大赛（如重庆市赛、四川省赛、浙江省赛等）金牌/亚军/冠军 —— 这些省赛≈CCPC省级赛事，有一定含金量（52-60分）
   - NOIP一等奖/CSP-S一等奖
   - **注意：区域赛铜牌 > 邀请赛银牌 > 省赛金牌，不要搞反**

   **B级（40-51分）—— 中等水平：**
   - ICPC/CCPC区域赛打铁（参赛但未获奖）
   - 省赛银牌/铜牌
   - NOIP二等奖
   - 邀请赛打铁

   **C级（25-39分）—— 入门水平：**
   - 蓝桥杯省一/国奖、天梯赛金奖、百度之星等非核心赛事（这些含金量远低于ICPC/CCPC/OI）
   - 只有校赛获奖

   **D级（10-24分）—— 边缘经历：**
   - 只有蓝桥杯省二省三、天梯赛银铜等
   - 只有Codeforces/LeetCode/牛客rating（在线平台不是正式比赛，仅辅助参考）

   **E级（0-9分）—— 无竞赛经历：**
   - 完全没有提到任何算法竞赛

   **重要提示：**
   - 有ICPC/CCPC/IOI/NOI成绩就按成绩打分，不需要看CF/LC等平台
   - 区域赛金牌很强（A+级），但不要和EC Final/WF混淆，后者更高一档
   - 省级程序设计大赛（XX省大学生程序设计大赛）≈ CCPC省级邀请赛，金牌约等于B+级

2. internship_project (实习/项目, 权重25%):
   评分综合考虑：**公司品牌 × 岗位含金量 × 工作内容质量**。不能只看公司名，岗位和内容同样重要。

   **S级（88-100分）—— 顶级经历：**
   - 一线大厂（字节跳动、阿里、腾讯、华为、美团、百度、Google、Meta、Microsoft、Amazon等）的**核心技术岗**（算法、后端开发、架构、基础设施等）
   - 头部量化私募/对冲基金（如Citadel、Two Sigma、Jane Street、幻方、九坤、衍复等）的**量化开发/策略研究**岗位——量化对算法能力要求极高，即使公司规模不大也应高分
   - 有详细的项目描述+量化成果（如"优化推荐系统CTR提升5%"、"交易系统延迟降低到微秒级"）

   **A级（70-87分）—— 优秀经历：**
   - 一线大厂的**非核心技术岗**（测试、运维、数据标注、产品等）—— 公司好但岗位技术含量一般，应低于同公司核心岗
   - 知名互联网公司（快手、网易、京东、小红书、拼多多、蚂蚁、滴滴等）的核心技术岗
   - 知名外企、独角兽创业公司的技术岗
   - 中小型量化公司的量化开发岗
   - 有具体项目内容和成果描述

   **B级（45-69分）—— 普通经历：**
   - 不知名中小公司的技术实习
   - 大厂的极短期实习（不到3个月）或描述非常简略
   - 有一定质量的个人项目/开源项目（如GitHub star较多的项目、有实际用户的产品）
   - 做的事情比较普通但有基本描述

   **C级（20-44分）—— 一般经历：**
   - 不知名小公司 + 做的事情很水（简单CRUD、搬砖式开发）
   - 只有课程项目、课设作业、毕设
   - 公司没听说过 + 项目描述也很一般

   **D级（0-19分）：**
   - 完全没有提到任何实习或项目经历

   **岗位含金量参考（同一公司内）：**
   算法/策略研究 > 后端/系统开发 > 前端/客户端 > 测试/运维/数据标注
   量化开发/量化策略（即使小公司）≈ 大厂核心技术岗

3. school (学校背景, 权重20%):

   **海外高校：**
   - 95-100: MIT、Stanford、CMU、Harvard、Princeton、Caltech、Oxford、Cambridge 等世界TOP10
   - 85-94: UC Berkeley、ETH Zurich、NUS、NTU、东京大学、多伦多大学、Columbia、Cornell、UIUC、Georgia Tech 等世界TOP50
   - 75-84: 其他QS/US News排名50-100的海外名校
   - 60-74: QS 100-300的海外高校
   - 40-59: 排名300以后或不知名的海外高校

   **国内高校：**
   - 95-100: 清华、北大
   - 85-94: 其他C9（复旦、上交、浙大、南大、中科大、哈工大、西交）
   - 75-84: 其他985高校
   - 60-74: 211高校
   - 40-59: 普通一本

   **计算机领域特别强的非211高校，可适当上浮到60-70分：**
   - 杭州电子科技大学、深圳大学、中国科学院大学、西湖大学、南方科技大学等
   - 这些学校虽然不是211，但在CS领域有较强实力，应高于普通一本

   - 20-39: 二本/三本/专科
   - 简历中没有提到学校信息 → 按双非本科处理，给30分，并在comment中注明"简历中未提及学校信息，按双非本科计算"
   - **同一所学校应该给相同的分数**，不要因为简历其他内容好坏而影响学校评分
   - 硕士/博士学历可在对应学校分数上+3-5分

4. tech_stack (技术栈深度, 权重15%):
   - 85-100: 技术栈丰富且有深度——多种语言+框架+数据库+中间件+系统设计，有具体实践描述（如"使用Redis做缓存优化，QPS提升3倍"）
   - 65-84: 技术栈较广但深度一般——列出了多种技术，有一定项目经验描述
   - 45-64: 基础技术栈——列出了几种语言和基础框架，描述简略
   - 25-44: 单薄——只提了1-2个语言名字，无具体经验
   - 0-24: 几乎没有技术栈信息

5. overall (综合素质, 权重10%):
   评价简历本身的质量，不是评价人：
   - 80-100: 内容充实（500字以上），结构清晰，描述具体有量化数据，排版专业
   - 55-79: 内容较完整，有基本的结构和描述
   - 30-54: 内容偏少（100-300字），部分关键信息缺失
   - 0-29: 内容过于简略（少于100字），或者不是简历内容

6. job_matches (岗位推荐):
   根据简历内容，推荐3-5个最匹配的岗位方向，并给出匹配度(0-100)和原因。
   岗位方向包括但不限于：
   - **量化开发** —— 算法竞赛能力强 + 有C++/Python底子
   - **量化策略/研究** —— 数学好 + 算法强 + 有数据分析能力
   - **后端开发** —— 有后端项目经验 + 熟悉数据库/框架
   - **算法工程师(AI/ML)** —— 有机器学习/深度学习经验
   - **基础架构(Infra)** —— 系统编程能力强 + 了解分布式/存储/网络
   - **AI Agent开发** —— 有LLM/Agent相关经验
   - **前端开发** —— 有前端项目经验
   - **客户端开发(iOS/Android)** —— 有移动端经验
   - **安全工程师** —— 有安全/CTF经验
   - **数据工程师** —— 有大数据处理经验
   - **嵌入式/IoT** —— 有硬件/嵌入式经验
   - **游戏开发** —— 有游戏引擎/图形学经验
   - **编译器/PL** —— 有编译原理/程序语言相关经验
   - **数据库内核** —— 有数据库开发经验

   匹配度评分规则：
   - 简历中有直接相关经历 → 80-100
   - 技能和背景高度相关但无直接经历 → 60-79
   - 有一定相关性 → 40-59
   - 只推荐匹配度>=50的岗位，按匹配度从高到低排列

total_score字段可以随便填（后端会自己按公式算），但各维度分数必须准确。

所有评价和建议必须用中文。在comment中，如果该维度信息缺失，请明确指出"简历中未提及相关信息"。`

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
