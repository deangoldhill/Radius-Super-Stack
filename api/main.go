package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var db *sqlx.DB
var jwtSecret []byte

func initDB() {
	host := getEnv("DB_HOST", "localhost")
	user := getEnv("DB_USER", "radius")
	pass := getEnv("DB_PASS", "radpass")
	dbname := getEnv("DB_NAME", "radius")
	jwtSecret = []byte(getEnv("JWT_SECRET", "super-secret-freeradius-key"))

	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, dbname)
	var err error
	db, err = sqlx.Connect("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getSetting(key, defaultVal string) string {
	var val string
	err := db.Get(&val, "SELECT key_value FROM api_settings WHERE key_name = ?", key)
	if err != nil {
		return defaultVal
	}
	return val
}

func logAudit(username, mode, action string) {
	_, err := db.Exec("INSERT INTO api_audit (admin_user, mode, action, created_at) VALUES (?, ?, ?, NOW())", username, mode, action)
	if err != nil {
		log.Println("Audit Error:", err)
	}
}

func authMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var userRoles, username, mode string

		apiKey := c.GetHeader("x-api-key")
		if apiKey != "" {
			var admin struct {
				Username string `db:"username"`
				Roles    string `db:"roles"`
			}
			if err := db.Get(&admin, "SELECT username, roles FROM api_admins WHERE api_key = ?", apiKey); err != nil {
				c.AbortWithStatusJSON(401, gin.H{"detail": "Invalid API Key"})
				return
			}
			userRoles = admin.Roles
			username = admin.Username
			mode = "API"
		} else {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.AbortWithStatusJSON(401, gin.H{"detail": "Missing Authentication"})
				return
			}
			token, err := jwt.Parse(strings.TrimPrefix(authHeader, "Bearer "), func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
			if err != nil || !token.Valid {
				c.AbortWithStatusJSON(401, gin.H{"detail": "Invalid Token"})
				return
			}
			claims, _ := token.Claims.(jwt.MapClaims)
			userRoles = claims["roles"].(string)
			username = claims["sub"].(string)
			mode = "Frontend"
		}

		if !strings.Contains(userRoles, requiredRole) && requiredRole != "" {
			c.AbortWithStatusJSON(403, gin.H{"detail": "Access Denied to Module"})
			return
		}
		if c.Request.Method != http.MethodGet && !strings.Contains(userRoles, "write") {
			c.AbortWithStatusJSON(403, gin.H{"detail": "Read-Only Access"})
			return
		}

		c.Set("user", username)
		c.Set("mode", mode)
		c.Next()
	}
}

func genToken(username, roles string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": username, "roles": roles, "exp": time.Now().Add(12 * time.Hour).Unix()})
	ts, _ := token.SignedString(jwtSecret)
	return ts
}

func main() {
	initDB()
	r := gin.Default()

	r.GET("/", func(c *gin.Context) { c.File("index.html") })

	v1 := r.Group("/api/v1")

	// AUTH
	v1.POST("/auth/login", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			return
		}
		var admin struct {
			Username string  `db:"username"`
			Hash     string  `db:"password_hash"`
			TOTP     *string `db:"totp_secret"`
			Roles    string  `db:"roles"`
		}
		if err := db.Get(&admin, "SELECT username, password_hash, totp_secret, roles FROM api_admins WHERE username = ?", req.Username); err != nil || bcrypt.CompareHashAndPassword([]byte(admin.Hash), []byte(req.Password)) != nil {
			c.JSON(401, gin.H{"detail": "Invalid credentials"})
			return
		}
		if admin.TOTP != nil && *admin.TOTP != "" {
			c.JSON(200, gin.H{"status": "2fa_required", "username": admin.Username})
			return
		}
		if getSetting("force_2fa", "false") == "true" {
			k, _ := totp.Generate(totp.GenerateOpts{Issuer: "FreeRADIUS", AccountName: admin.Username})
			c.JSON(200, gin.H{"status": "setup_2fa_required", "username": admin.Username, "qr_uri": k.URL(), "secret": k.Secret()})
			return
		}
		logAudit(admin.Username, "Frontend", "Logged in")
		c.JSON(200, gin.H{"status": "success", "token": genToken(admin.Username, admin.Roles)})
	})
	v1.POST("/auth/verify-2fa", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Code     string `json:"code"`
		}
		c.BindJSON(&req)
		var admin struct {
			TOTP  *string `db:"totp_secret"`
			Roles string  `db:"roles"`
		}
		if err := db.Get(&admin, "SELECT totp_secret, roles FROM api_admins WHERE username = ?", req.Username); err != nil || admin.TOTP == nil || !totp.Validate(req.Code, *admin.TOTP) {
			c.JSON(401, gin.H{"detail": "Invalid 2FA Request"})
			return
		}
		logAudit(req.Username, "Frontend", "Logged in via 2FA")
		c.JSON(200, gin.H{"status": "success", "token": genToken(req.Username, admin.Roles)})
	})
	v1.POST("/auth/setup-2fa", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Secret   string `json:"secret"`
			Code     string `json:"code"`
		}
		c.BindJSON(&req)
		var admin struct {
			Hash  string `db:"password_hash"`
			Roles string `db:"roles"`
		}
		if err := db.Get(&admin, "SELECT password_hash, roles FROM api_admins WHERE username = ?", req.Username); err != nil || bcrypt.CompareHashAndPassword([]byte(admin.Hash), []byte(req.Password)) != nil {
			c.JSON(401, gin.H{"detail": "Invalid credentials"})
			return
		}
		if !totp.Validate(req.Code, req.Secret) {
			c.JSON(401, gin.H{"detail": "Invalid Setup Code"})
			return
		}
		db.Exec("UPDATE api_admins SET totp_secret = ? WHERE username = ?", req.Secret, req.Username)
		logAudit(req.Username, "Frontend", "Forced 2FA Setup Completed")
		c.JSON(200, gin.H{"status": "success", "token": genToken(req.Username, admin.Roles)})
	})

	// SETTINGS & SYSTEM STATUS
	v1.GET("/settings", authMiddleware(""), func(c *gin.Context) {
		var rows []struct {
			Key   string `db:"key_name"`
			Value string `db:"key_value"`
		}
		db.Select(&rows, "SELECT key_name, key_value FROM api_settings")
		m := make(map[string]string)
		for _, r := range rows {
			m[r.Key] = r.Value
		}
		c.JSON(200, gin.H{"status": "success", "data": m})
	})
	v1.POST("/settings", authMiddleware("write"), func(c *gin.Context) {
		var req map[string]string
		c.BindJSON(&req)
		for k, v := range req {
			db.Exec("INSERT INTO api_settings (key_name, key_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE key_value = ?", k, v, v)
		}
		logAudit(c.GetString("user"), c.GetString("mode"), "Updated System Settings")
		c.JSON(200, gin.H{"status": "success"})
	})

	v1.GET("/system/status", authMiddleware(""), func(c *gin.Context) {
		var dbSize float64
		db.Get(&dbSize, "SELECT COALESCE(SUM(data_length + index_length)/1024/1024, 0) FROM information_schema.TABLES WHERE table_schema = 'radius'")

		type TableStat struct {
			Name   string  `db:"table_name" json:"name"`
			Rows   int     `db:"table_rows" json:"rows"`
			SizeMB float64 `db:"size_mb" json:"size_mb"`
		}
		var tables []TableStat
		db.Select(&tables, "SELECT table_name, COALESCE(table_rows,0) as table_rows, ROUND(((data_length + index_length) / 1024 / 1024), 3) AS size_mb FROM information_schema.TABLES WHERE table_schema = 'radius' ORDER BY size_mb DESC")

		var uptime struct {
			Name  string `db:"Variable_name"`
			Value string `db:"Value"`
		}
		db.Get(&uptime, "SHOW GLOBAL STATUS LIKE 'Uptime'")

		out, err := exec.Command("docker", "inspect", "--format", "{{.State.Status}}", "radius_server").Output()
		radStatus := "offline"
		if err == nil {
			radStatus = strings.TrimSpace(string(out))
		}

		c.JSON(200, gin.H{"status": "success", "db_size_mb": dbSize, "tables": tables, "radius_status": radStatus, "db_uptime": uptime.Value})
	})

	v1.POST("/system/radius/restart", authMiddleware("write"), func(c *gin.Context) {
		exec.Command("docker", "restart", "radius_server").Run()
		logAudit(c.GetString("user"), c.GetString("mode"), "Restarted FreeRADIUS Service")
		c.JSON(200, gin.H{"status": "success"})
	})

	// CERTIFICATES 
	v1.GET("/system/certs/info", authMiddleware(""), func(c *gin.Context) {
		out, err := exec.Command("docker", "exec", "radius_server", "openssl", "x509", "-in", "/opt/etc/raddb/certs/server.pem", "-noout", "-subject", "-issuer", "-dates").Output()
		if err != nil {
			c.JSON(500, gin.H{"detail": "Could not read active certificate details. Certificate might be missing."})
			return
		}
		
		lines := strings.Split(string(out), "\n")
		info := make(map[string]string)
		for _, line := range lines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				info[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		c.JSON(200, gin.H{"status": "success", "data": info})
	})

	v1.POST("/system/certs", authMiddleware("write"), func(c *gin.Context) {
		var req struct {
			C    string `json:"c"`
			ST   string `json:"st"`
			L    string `json:"l"`
			O    string `json:"o"`
			CN   string `json:"cn"`
			Days int    `json:"days"`
		}
		c.BindJSON(&req)
		if req.Days == 0 {
			req.Days = 3650
		}

		script := `
import os
import re

def update_file(filepath, is_server):
    with open(filepath, 'r') as f:
        content = f.read()
    
    replacements = {
        'countryName': os.environ.get('CERT_C', ''),
        'stateOrProvinceName': os.environ.get('CERT_ST', ''),
        'localityName': os.environ.get('CERT_L', ''),
        'organizationName': os.environ.get('CERT_O', ''),
        'commonName': os.environ.get('CERT_CN', '') + (' Server' if is_server else ' CA'),
        'default_days': os.environ.get('CERT_DAYS', '3650')
    }
    
    for key, val in replacements.items():
        if val:
            val = val.replace('\\', '\\\\')
            content = re.sub(r'^\s*' + key + r'\s*=.*', key + ' = ' + val, content, flags=re.MULTILINE)
            
    with open(filepath, 'w') as f:
        f.write(content)

update_file('/opt/etc/raddb/certs/ca.cnf', False)
update_file('/opt/etc/raddb/certs/server.cnf', True)
`

		cmdStr := fmt.Sprintf(`cat << 'EOF' > /tmp/update_certs.py
%s
EOF
python3 /tmp/update_certs.py && \
cd /opt/etc/raddb/certs && \
rm -f *.pem *.der *.csr *.crt *.key *.p12 serial* index.txt* && \
make all && \
chown -R radius:radius /opt/etc/raddb/certs/ || true`, script)

		cmd := exec.Command("docker", "exec",
			"-e", "CERT_C="+req.C,
			"-e", "CERT_ST="+req.ST,
			"-e", "CERT_L="+req.L,
			"-e", "CERT_O="+req.O,
			"-e", "CERT_CN="+req.CN,
			"-e", fmt.Sprintf("CERT_DAYS=%d", req.Days),
			"radius_server", "sh", "-c", cmdStr)

		if out, err := cmd.CombinedOutput(); err != nil {
			c.JSON(500, gin.H{"detail": "Cert gen failed: " + string(out)})
			return
		}
		exec.Command("docker", "restart", "radius_server").Run()
		logAudit(c.GetString("user"), c.GetString("mode"), "Generated new EAP Certificates")
		c.JSON(200, gin.H{"status": "success"})
	})

	// Safely accepts uploaded certs and decrypts key if password is provided
	v1.POST("/system/certs/upload", authMiddleware("write"), func(c *gin.Context) {
		certFile, err := c.FormFile("certificate")
		if err != nil {
			c.JSON(400, gin.H{"detail": "Certificate file is required"})
			return
		}
		keyFile, err := c.FormFile("private_key")
		if err != nil {
			c.JSON(400, gin.H{"detail": "Private key file is required"})
			return
		}
		caFile, _ := c.FormFile("ca_certificate")
		keyPass := c.PostForm("key_password")

		os.MkdirAll("/tmp/certs", 0755)
		c.SaveUploadedFile(certFile, "/tmp/certs/server.pem")
		c.SaveUploadedFile(keyFile, "/tmp/certs/upload.key")
		
		if caFile != nil {
			c.SaveUploadedFile(caFile, "/tmp/certs/ca.pem")
		} else {
			// Fallback to server cert as CA if none provided
			c.SaveUploadedFile(certFile, "/tmp/certs/ca.pem")
		}

		exec.Command("docker", "cp", "/tmp/certs/server.pem", "radius_server:/opt/etc/raddb/certs/server.pem").Run()
		exec.Command("docker", "cp", "/tmp/certs/upload.key", "radius_server:/tmp/upload.key").Run()
		exec.Command("docker", "cp", "/tmp/certs/ca.pem", "radius_server:/opt/etc/raddb/certs/ca.pem").Run()

		var processCmd string
		if keyPass != "" {
			escapedPass := strings.ReplaceAll(keyPass, "'", "'\\''")
			processCmd = fmt.Sprintf("openssl rsa -in /tmp/upload.key -passin pass:'%s' -out /opt/etc/raddb/certs/server.key", escapedPass)
		} else {
			processCmd = "cp /tmp/upload.key /opt/etc/raddb/certs/server.key"
		}

		cmdStr := fmt.Sprintf(`%s && chown -R radius:radius /opt/etc/raddb/certs/ && rm -f /tmp/upload.key`, processCmd)
		cmd := exec.Command("docker", "exec", "radius_server", "sh", "-c", cmdStr)
		
		if out, err := cmd.CombinedOutput(); err != nil {
			c.JSON(500, gin.H{"detail": "Failed to process uploaded certs (Invalid password or format): " + string(out)})
			return
		}

		exec.Command("docker", "restart", "radius_server").Run()
		logAudit(c.GetString("user"), c.GetString("mode"), "Uploaded Custom SSL Certificates")
		c.JSON(200, gin.H{"status": "success"})
	})

	// Downloads by converting PEM to DER on the fly, avoiding "file not found" errors
	v1.GET("/system/certs/download", func(c *gin.Context) {
		out, err := exec.Command("docker", "exec", "radius_server", "sh", "-c", "openssl x509 -inform PEM -outform DER -in /opt/etc/raddb/certs/ca.pem").Output()
		if err != nil {
			c.String(500, "Certificate not found on server")
			return
		}
		c.Header("Content-Disposition", "attachment; filename=radius_ca.der")
		c.Data(200, "application/x-x509-ca-cert", out)
	})

	// REPORTS
	v1.GET("/reports/user", authMiddleware("reporting"), func(c *gin.Context) {
		u := c.Query("username")
		s := c.Query("start_date") + " 00:00:00"
		e := c.Query("end_date") + " 23:59:59"

		acctQuery := "FROM radacct WHERE acctstarttime >= ? AND acctstarttime <= ?"
		authQuery := "FROM radpostauth WHERE authdate >= ? AND authdate <= ?"
		var args []interface{}
		args = append(args, s, e)

		if u == "__unknown__" {
			acctQuery += " AND username NOT IN (SELECT username FROM radcheck)"
			authQuery += " AND username NOT IN (SELECT username FROM radcheck)"
		} else if u != "" {
			acctQuery += " AND username = ?"
			authQuery += " AND username = ?"
			args = append(args, u)
		}

		var summary struct {
			TotalDown     int64 `db:"total_down" json:"total_down"`
			TotalUp       int64 `db:"total_up" json:"total_up"`
			TotalSessions int   `db:"total_sessions" json:"total_sessions"`
			TotalTime     int   `db:"total_time" json:"total_time"`
		}
		db.Get(&summary, "SELECT COALESCE(SUM(acctoutputoctets),0) as total_down, COALESCE(SUM(acctinputoctets),0) as total_up, COUNT(radacctid) as total_sessions, COALESCE(SUM(acctsessiontime),0) as total_time "+acctQuery, args...)

		var authSummary struct {
			TotalAuths int `db:"total_auths" json:"total_auths"`
			Accepts    int `db:"accepts" json:"accepts"`
			Rejects    int `db:"rejects" json:"rejects"`
		}
		db.Get(&authSummary, "SELECT COUNT(id) as total_auths, COALESCE(SUM(IF(reply='Access-Accept',1,0)),0) as accepts, COALESCE(SUM(IF(reply='Access-Reject',1,0)),0) as rejects "+authQuery, args...)

		type Daily struct { Day string `db:"day" json:"day"`; Up int64 `db:"up" json:"up"`; Down int64 `db:"down" json:"down"` }
		var daily []Daily
		db.Select(&daily, "SELECT DATE(acctstarttime) as day, COALESCE(SUM(acctinputoctets),0) as up, COALESCE(SUM(acctoutputoctets),0) as down "+acctQuery+" GROUP BY day ORDER BY day ASC", args...)

		type NasDist struct { NasIP string `db:"nasipaddress" json:"nasipaddress"`; Bytes int64 `db:"total_bytes" json:"total_bytes"` }
		var nasDist []NasDist
		db.Select(&nasDist, "SELECT nasipaddress, COALESCE(SUM(acctinputoctets + acctoutputoctets),0) as total_bytes "+acctQuery+" GROUP BY nasipaddress ORDER BY total_bytes DESC", args...)

		type AuthDaily struct { Day string `db:"day" json:"day"`; Accepts int `db:"accepts" json:"accepts"`; Rejects int `db:"rejects" json:"rejects"` }
		var authDaily []AuthDaily
		db.Select(&authDaily, "SELECT DATE(authdate) as day, COALESCE(SUM(IF(reply='Access-Accept',1,0)),0) as accepts, COALESCE(SUM(IF(reply='Access-Reject',1,0)),0) as rejects "+authQuery+" GROUP BY day ORDER BY day ASC", args...)

		type TopSession struct { Start *time.Time `db:"acctstarttime" json:"acctstarttime"`; Time int `db:"acctsessiontime" json:"acctsessiontime"`; FIP string `db:"framedipaddress" json:"framedipaddress"`; NIP string `db:"nasipaddress" json:"nasipaddress"`; Up int64 `db:"acctinputoctets" json:"up"`; Down int64 `db:"acctoutputoctets" json:"down"` }
		var topSessions []TopSession
		db.Select(&topSessions, "SELECT acctstarttime, COALESCE(acctsessiontime,0) as acctsessiontime, framedipaddress, nasipaddress, COALESCE(acctinputoctets,0) as acctinputoctets, COALESCE(acctoutputoctets,0) as acctoutputoctets "+acctQuery+" ORDER BY (acctinputoctets + acctoutputoctets) DESC LIMIT 15", args...)

		c.JSON(200, gin.H{"status": "success", "data": gin.H{"summary": summary, "auth_summary": authSummary, "daily": daily, "nas_distribution": nasDist, "auth_daily": authDaily, "top_sessions": topSessions}})
	})

	v1.GET("/reports/failed-auths", authMiddleware("reporting"), func(c *gin.Context) {
		s := c.Query("start_date") + " 00:00:00"
		e := c.Query("end_date") + " 23:59:59"

		type Daily struct { Day string `db:"day" json:"day"`; Fails int `db:"fails" json:"fails"` }
		var daily []Daily
		db.Select(&daily, "SELECT DATE(authdate) as day, COUNT(id) as fails FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= ? AND authdate <= ? GROUP BY day ORDER BY day ASC", s, e)

		type TopUser struct { Username string `db:"username" json:"username"`; Failures int `db:"failures" json:"failures"` }
		var topUsers []TopUser
		db.Select(&topUsers, "SELECT username, COUNT(id) as failures FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= ? AND authdate <= ? GROUP BY username ORDER BY failures DESC LIMIT 10", s, e)

		type Recent struct { AuthDate *time.Time `db:"authdate" json:"authdate"`; Username string `db:"username" json:"username"` }
		var recent []Recent
		db.Select(&recent, "SELECT authdate, username FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= ? AND authdate <= ? ORDER BY authdate DESC LIMIT 50", s, e)

		c.JSON(200, gin.H{"status": "success", "data": gin.H{"daily": daily, "top_users": topUsers, "recent": recent}})
	})

	// PROFILES
	type ProfileAttr struct {
		Attribute string `json:"attribute"`
		Value     string `json:"value"`
	}
	v1.GET("/profiles", authMiddleware("profiles"), func(c *gin.Context) {
		type ProfileData struct {
			Groupname       string        `json:"groupname"`
			Vlan            int           `json:"vlan"`
			Attributes      []ProfileAttr `json:"attributes"`
			NasRestrictions []string      `json:"nas_restrictions"`
		}
		pm := make(map[string]*ProfileData)

		var repRows []struct {
			Groupname string `db:"groupname"`
			Attribute string `db:"attribute"`
			Value     string `db:"value"`
		}
		db.Select(&repRows, "SELECT groupname, attribute, value FROM radgroupreply")
		for _, r := range repRows {
			if pm[r.Groupname] == nil {
				pm[r.Groupname] = &ProfileData{Groupname: r.Groupname, Attributes: []ProfileAttr{}, NasRestrictions: []string{}}
			}
			if r.Attribute == "Tunnel-Private-Group-ID" {
				fmt.Sscanf(r.Value, "%d", &pm[r.Groupname].Vlan)
			} else if r.Attribute != "Tunnel-Type" && r.Attribute != "Tunnel-Medium-Type" {
				pm[r.Groupname].Attributes = append(pm[r.Groupname].Attributes, ProfileAttr{Attribute: r.Attribute, Value: r.Value})
			}
		}

		var chkRows []struct {
			Groupname string `db:"groupname"`
			Value     string `db:"value"`
		}
		db.Select(&chkRows, "SELECT groupname, value FROM radgroupcheck WHERE attribute = 'NAS-IP-Address'")
		for _, r := range chkRows {
			if pm[r.Groupname] == nil {
				pm[r.Groupname] = &ProfileData{Groupname: r.Groupname, Attributes: []ProfileAttr{}, NasRestrictions: []string{}}
			}
			pm[r.Groupname].NasRestrictions = append(pm[r.Groupname].NasRestrictions, r.Value)
		}

		var res []ProfileData
		for _, p := range pm {
			if p.NasRestrictions == nil {
				p.NasRestrictions = []string{}
			}
			res = append(res, *p)
		}
		sort.Slice(res, func(i, j int) bool { return res[i].Groupname < res[j].Groupname })
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.POST("/profiles", authMiddleware("profiles"), func(c *gin.Context) {
		var req struct {
			Groupname string `json:"groupname"`
			Vlan      int    `json:"vlan"`
		}
		c.BindJSON(&req)
		db.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Tunnel-Type', '=', '13'), (?, 'Tunnel-Medium-Type', '=', '6'), (?, 'Tunnel-Private-Group-ID', '=', ?)", req.Groupname, req.Groupname, req.Groupname, fmt.Sprintf("%d", req.Vlan))
		logAudit(c.GetString("user"), c.GetString("mode"), "Created Profile: "+req.Groupname)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.PUT("/profiles/:groupname", authMiddleware("profiles"), func(c *gin.Context) {
		var req struct {
			Vlan int `json:"vlan"`
		}
		c.BindJSON(&req)
		db.Exec("UPDATE radgroupreply SET value = ? WHERE groupname = ? AND attribute = 'Tunnel-Private-Group-ID'", fmt.Sprintf("%d", req.Vlan), c.Param("groupname"))
		logAudit(c.GetString("user"), c.GetString("mode"), "Updated Profile VLAN: "+c.Param("groupname"))
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.DELETE("/profiles/:groupname", authMiddleware("profiles"), func(c *gin.Context) {
		g := c.Param("groupname")
		db.Exec("DELETE FROM radgroupreply WHERE groupname = ?", g)
		db.Exec("DELETE FROM radusergroup WHERE groupname = ?", g)
		db.Exec("DELETE FROM radgroupcheck WHERE groupname = ?", g)
		logAudit(c.GetString("user"), c.GetString("mode"), "Deleted Profile: "+g)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.POST("/profiles/:groupname/attrs", authMiddleware("profiles"), func(c *gin.Context) {
		if getSetting("enable_profile_attrs", "true") != "true" {
			c.JSON(403, gin.H{"detail": "Profile attributes disabled"})
			return
		}
		var req struct {
			Attribute string `json:"attribute"`
			Value     string `json:"value"`
		}
		c.BindJSON(&req)
		g := c.Param("groupname")
		db.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, ?, '=', ?)", g, req.Attribute, req.Value)
		logAudit(c.GetString("user"), c.GetString("mode"), "Added attribute "+req.Attribute+" to "+g)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.DELETE("/profiles/:groupname/attrs", authMiddleware("profiles"), func(c *gin.Context) {
		g := c.Param("groupname")
		attr := c.Query("attribute")
		db.Exec("DELETE FROM radgroupreply WHERE groupname = ? AND attribute = ?", g, attr)
		logAudit(c.GetString("user"), c.GetString("mode"), "Deleted attribute "+attr+" from "+g)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.POST("/profiles/:groupname/nas", authMiddleware("profiles"), func(c *gin.Context) {
		var req struct {
			IP string `json:"ip"`
		}
		c.BindJSON(&req)
		g := c.Param("groupname")
		db.Exec("INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'NAS-IP-Address', '==', ?)", g, req.IP)
		logAudit(c.GetString("user"), c.GetString("mode"), "Added NAS Restriction "+req.IP+" to "+g)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.DELETE("/profiles/:groupname/nas", authMiddleware("profiles"), func(c *gin.Context) {
		g := c.Param("groupname")
		ip := c.Query("ip")
		db.Exec("DELETE FROM radgroupcheck WHERE groupname = ? AND attribute = 'NAS-IP-Address' AND value = ?", g, ip)
		logAudit(c.GetString("user"), c.GetString("mode"), "Removed NAS Restriction "+ip+" from "+g)
		c.JSON(200, gin.H{"status": "success"})
	})

	// USERS
	v1.GET("/users", authMiddleware(""), func(c *gin.Context) {
		var users []string
		db.Select(&users, "SELECT DISTINCT username FROM radcheck WHERE username != '' ORDER BY username ASC")
		c.JSON(200, gin.H{"status": "success", "data": users})
	})
	v1.GET("/users-summary", authMiddleware("users"), func(c *gin.Context) {
		type Attr struct {
			Attribute string `json:"attribute"`
			Op        string `json:"op"`
			Value     string `json:"value"`
		}
		type UserSummary struct {
			Username   string  `json:"username"`
			Up         int64   `json:"upload_31d"`
			Down       int64   `json:"download_31d"`
			Attributes []Attr  `json:"attributes"`
			Profile    *string `json:"profile"`
		}

		var rows []struct {
			Username string `db:"username"`
			Up       int64  `db:"up"`
			Down     int64  `db:"down"`
		}
		db.Select(&rows, "SELECT username, COALESCE(SUM(acctinputoctets), 0) as up, COALESCE(SUM(acctoutputoctets), 0) as down FROM radacct WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 31 DAY) AND username != '' GROUP BY username")
		um := make(map[string]*UserSummary)
		for _, r := range rows {
			um[r.Username] = &UserSummary{Username: r.Username, Up: r.Up, Down: r.Down, Attributes: []Attr{}}
		}

		var attrs []struct {
			Username  string `db:"username"`
			Attribute string `db:"attribute"`
			Op        string `db:"op"`
			Value     string `db:"value"`
		}
		db.Select(&attrs, "SELECT username, attribute, op, value FROM radcheck UNION ALL SELECT username, attribute, op, value FROM radreply")
		for _, a := range attrs {
			if _, ok := um[a.Username]; !ok {
				um[a.Username] = &UserSummary{Username: a.Username, Attributes: []Attr{}}
			}
			val := a.Value
			if a.Attribute == "Cleartext-Password" {
				val = "********"
			}
			um[a.Username].Attributes = append(um[a.Username].Attributes, Attr{Attribute: a.Attribute, Op: a.Op, Value: val})
		}
		var profs []struct {
			Username  string `db:"username"`
			Groupname string `db:"groupname"`
		}
		db.Select(&profs, "SELECT username, groupname FROM radusergroup")
		for _, p := range profs {
			if _, ok := um[p.Username]; ok {
				grp := p.Groupname
				um[p.Username].Profile = &grp
			}
		}

		res := []UserSummary{}
		for _, u := range um {
			res = append(res, *u)
		}
		sort.Slice(res, func(i, j int) bool { return res[i].Username < res[j].Username })
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.POST("/users", authMiddleware("users"), func(c *gin.Context) {
		var req struct {
			Username string  `json:"username"`
			Password string  `json:"password"`
			Profile  *string `json:"profile"`
		}
		c.BindJSON(&req)
		db.Exec("INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)", req.Username, req.Password)
		if req.Profile != nil && *req.Profile != "" {
			db.Exec("INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)", req.Username, *req.Profile)
		}
		logAudit(c.GetString("user"), c.GetString("mode"), "Created User: "+req.Username)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.POST("/users/bulk", authMiddleware("users"), func(c *gin.Context) {
		if getSetting("enable_bulk_import", "true") != "true" {
			c.JSON(403, gin.H{"detail": "Bulk importing is disabled globally"})
			return
		}
		var users []struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Profile  string `json:"profile"`
			IP       string `json:"ip"`
		}
		c.BindJSON(&users)
		count := 0
		for _, u := range users {
			if u.Username == "" {
				continue
			}
			db.Exec("INSERT IGNORE INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)", u.Username, u.Password)
			if u.Profile != "" {
				db.Exec("INSERT IGNORE INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)", u.Username, u.Profile)
			}
			if u.IP != "" {
				db.Exec("INSERT IGNORE INTO radreply (username, attribute, op, value) VALUES (?, 'Framed-IP-Address', ':=', ?)", u.Username, u.IP)
			}
			count++
		}
		logAudit(c.GetString("user"), c.GetString("mode"), fmt.Sprintf("Bulk imported %d users", count))
		c.JSON(200, gin.H{"status": "success", "imported": count})
	})
	v1.PUT("/users/:username/password", authMiddleware("users"), func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
		}
		c.BindJSON(&req)
		u := c.Param("username")
		res, _ := db.Exec("UPDATE radcheck SET value = ? WHERE username = ? AND attribute = 'Cleartext-Password'", req.Password, u)
		if rows, _ := res.RowsAffected(); rows == 0 {
			db.Exec("INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)", u, req.Password)
		}
		logAudit(c.GetString("user"), c.GetString("mode"), "Reset Password for User: "+u)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.PUT("/users/:username/profile", authMiddleware("users"), func(c *gin.Context) {
		var req struct {
			Profile *string `json:"profile"`
		}
		c.BindJSON(&req)
		u := c.Param("username")
		db.Exec("DELETE FROM radusergroup WHERE username = ?", u)
		if req.Profile != nil && *req.Profile != "" {
			db.Exec("INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)", u, *req.Profile)
		}
		logAudit(c.GetString("user"), c.GetString("mode"), "Updated Profile for User: "+u)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.PUT("/users/:username/static-ip", authMiddleware("users"), func(c *gin.Context) {
		var req struct {
			IP string `json:"ip"`
		}
		c.BindJSON(&req)
		u := c.Param("username")
		if req.IP == "" {
			db.Exec("DELETE FROM radreply WHERE username = ? AND attribute = 'Framed-IP-Address'", u)
		} else {
			res, _ := db.Exec("UPDATE radreply SET value = ? WHERE username = ? AND attribute = 'Framed-IP-Address'", req.IP, u)
			if rows, _ := res.RowsAffected(); rows == 0 {
				db.Exec("INSERT INTO radreply (username, attribute, op, value) VALUES (?, 'Framed-IP-Address', ':=', ?)", u, req.IP)
			}
		}
		logAudit(c.GetString("user"), c.GetString("mode"), "Updated Static IP for User: "+u)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.DELETE("/users/:username", authMiddleware("users"), func(c *gin.Context) {
		u := c.Param("username")
		db.Exec("DELETE FROM radcheck WHERE username = ?", u)
		db.Exec("DELETE FROM radreply WHERE username = ?", u)
		db.Exec("DELETE FROM radusergroup WHERE username = ?", u)
		db.Exec("DELETE FROM radacct WHERE username = ?", u)
		db.Exec("DELETE FROM radpostauth WHERE username = ?", u)
		logAudit(c.GetString("user"), c.GetString("mode"), "Deleted User completely: "+u)
		c.JSON(200, gin.H{"status": "success"})
	})

	// ACCOUNTING
	v1.GET("/online-users", authMiddleware("active"), func(c *gin.Context) {
		type OnlineSession struct {
			Username         string     `db:"username" json:"username"`
			NasIPAddress     string     `db:"nasipaddress" json:"nasipaddress"`
			FramedIPAddress  string     `db:"framedipaddress" json:"framedipaddress"`
			AcctStartTime    *time.Time `db:"acctstarttime" json:"acctstarttime"`
			AcctSessionID    string     `db:"acctsessionid" json:"acctsessionid"`
			AcctInputOctets  int64      `db:"acctinputoctets" json:"acctinputoctets"`
			AcctOutputOctets int64      `db:"acctoutputoctets" json:"acctoutputoctets"`
		}
		var res []OnlineSession
		db.Select(&res, "SELECT username, nasipaddress, framedipaddress, acctstarttime, acctsessionid, COALESCE(acctinputoctets, 0) as acctinputoctets, COALESCE(acctoutputoctets, 0) as acctoutputoctets FROM radacct WHERE acctstoptime IS NULL ORDER BY acctstarttime DESC")
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.GET("/closed-sessions", authMiddleware("history"), func(c *gin.Context) {
		type ClosedSession struct {
			Username    string     `db:"username" json:"username"`
			NasIP       string     `db:"nasipaddress" json:"nasipaddress"`
			FramedIP    string     `db:"framedipaddress" json:"framedipaddress"`
			Start       *time.Time `db:"acctstarttime" json:"acctstarttime"`
			Stop        *time.Time `db:"acctstoptime" json:"acctstoptime"`
			SessionTime int        `db:"acctsessiontime" json:"acctsessiontime"`
			Input       int64      `db:"acctinputoctets" json:"acctinputoctets"`
			Output      int64      `db:"acctoutputoctets" json:"acctoutputoctets"`
			TermCause   string     `db:"acctterminatecause" json:"acctterminatecause"`
		}
		q := "SELECT username, nasipaddress, framedipaddress, acctstarttime, acctstoptime, acctsessiontime, COALESCE(acctinputoctets, 0) as acctinputoctets, COALESCE(acctoutputoctets, 0) as acctoutputoctets, COALESCE(acctterminatecause, '') as acctterminatecause FROM radacct WHERE acctstoptime IS NOT NULL"
		args := []interface{}{}
		if u := c.Query("username"); u == "__unknown__" {
			q += " AND username NOT IN (SELECT username FROM radcheck)"
		} else if u != "" {
			q += " AND username = ?"
			args = append(args, u)
		}
		if s := c.Query("start_date"); s != "" {
			q += " AND acctstarttime >= ?"
			args = append(args, s+" 00:00:00")
		}
		if e := c.Query("end_date"); e != "" {
			q += " AND acctstoptime <= ?"
			args = append(args, e+" 23:59:59")
		}
		var res []ClosedSession
		db.Select(&res, q+" ORDER BY acctstoptime DESC LIMIT 200", args...)
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.DELETE("/closed-sessions", authMiddleware("history"), func(c *gin.Context) {
		if getSetting("enable_purge_accounting", "true") != "true" {
			c.JSON(403, gin.H{"detail": "Purging accounting logs is disabled globally"})
			return
		}
		q := "DELETE FROM radacct WHERE acctstoptime IS NOT NULL AND acctstoptime >= ? AND acctstoptime <= ?"
		args := []interface{}{c.Query("start_date") + " 00:00:00", c.Query("end_date") + " 23:59:59"}
		u := c.Query("username")
		if u == "__unknown__" {
			q += " AND username NOT IN (SELECT username FROM radcheck)"
		} else if u != "" {
			q += " AND username = ?"
			args = append(args, u)
		}
		res, _ := db.Exec(q, args...)
		rows, _ := res.RowsAffected()
		logAudit(c.GetString("user"), c.GetString("mode"), fmt.Sprintf("Purged %d accounting records", rows))
		c.JSON(200, gin.H{"status": "success", "deleted_rows": rows})
	})

	// AUTH LOGS
	v1.GET("/auth-logs", authMiddleware("authlogs"), func(c *gin.Context) {
		q := "SELECT username, authdate, reply FROM radpostauth WHERE 1=1"
		args := []interface{}{}
		if u := c.Query("username"); u == "__unknown__" {
			q += " AND username NOT IN (SELECT username FROM radcheck)"
		} else if u != "" {
			q += " AND username = ?"
			args = append(args, u)
		}
		if s := c.Query("start_date"); s != "" {
			q += " AND authdate >= ?"
			args = append(args, s+" 00:00:00")
		}
		if e := c.Query("end_date"); e != "" {
			q += " AND authdate <= ?"
			args = append(args, e+" 23:59:59")
		}
		if r := c.Query("result"); r == "Accept" {
			q += " AND reply = 'Access-Accept'"
		} else if r == "Reject" {
			q += " AND reply = 'Access-Reject'"
		}
		var res []struct {
			Username string     `db:"username" json:"username"`
			Authdate *time.Time `db:"authdate" json:"authdate"`
			Reply    string     `db:"reply" json:"reply"`
		}
		db.Select(&res, q+" ORDER BY authdate DESC LIMIT 1000", args...)
		for i, r := range res {
			if r.Reply == "Access-Accept" {
				res[i].Reply = "Accept"
			} else if r.Reply == "Access-Reject" {
				res[i].Reply = "Reject"
			}
		}
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.DELETE("/auth-logs", authMiddleware("authlogs"), func(c *gin.Context) {
		if getSetting("enable_purge_authlogs", "true") != "true" {
			c.JSON(403, gin.H{"detail": "Purging auth logs is disabled globally"})
			return
		}
		q := "DELETE FROM radpostauth WHERE authdate >= ? AND authdate <= ?"
		args := []interface{}{c.Query("start_date") + " 00:00:00", c.Query("end_date") + " 23:59:59"}
		u := c.Query("username")
		if u == "__unknown__" {
			q += " AND username NOT IN (SELECT username FROM radcheck)"
		} else if u != "" {
			q += " AND username = ?"
			args = append(args, u)
		}
		res, _ := db.Exec(q, args...)
		rows, _ := res.RowsAffected()
		logAudit(c.GetString("user"), c.GetString("mode"), fmt.Sprintf("Purged %d auth logs", rows))
		c.JSON(200, gin.H{"status": "success", "deleted_rows": rows})
	})

	// CLIENTS, ADMINS, AUDIT
	v1.GET("/clients", authMiddleware("clients"), func(c *gin.Context) {
		type Client struct {
			ID          int     `db:"id" json:"id"`
			Nasname     string  `db:"nasname" json:"nasname"`
			Shortname   string  `db:"shortname" json:"shortname"`
			Type        string  `db:"type" json:"type"`
			Secret      string  `db:"secret" json:"secret"`
			Description *string `db:"description" json:"description"`
		}
		var res []Client
		db.Select(&res, "SELECT id, nasname, shortname, type, secret, description FROM nas ORDER BY nasname ASC")
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.POST("/clients", authMiddleware("clients"), func(c *gin.Context) {
		var r struct {
			Nasname   string `json:"nasname"`
			Shortname string `json:"shortname"`
			Type      string `json:"type"`
			Secret    string `json:"secret"`
			Desc      string `json:"description"`
		}
		c.BindJSON(&r)
		if strings.TrimSpace(r.Shortname) == "" {
			c.JSON(400, gin.H{"detail": "Shortname is mandatory"})
			return
		}
		db.Exec("INSERT INTO nas (nasname, shortname, type, secret, description) VALUES (?, ?, ?, ?, ?)", r.Nasname, r.Shortname, r.Type, r.Secret, r.Desc)
		logAudit(c.GetString("user"), c.GetString("mode"), "Added Client: "+r.Nasname)
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.PUT("/clients/:id", authMiddleware("clients"), func(c *gin.Context) {
		var r struct {
			Nasname   string `json:"nasname"`
			Shortname string `json:"shortname"`
			Type      string `json:"type"`
			Secret    string `json:"secret"`
			Desc      string `json:"description"`
		}
		c.BindJSON(&r)
		if strings.TrimSpace(r.Shortname) == "" {
			c.JSON(400, gin.H{"detail": "Shortname is mandatory"})
			return
		}
		db.Exec("UPDATE nas SET nasname=?, shortname=?, type=?, secret=?, description=? WHERE id=?", r.Nasname, r.Shortname, r.Type, r.Secret, r.Desc, c.Param("id"))
		logAudit(c.GetString("user"), c.GetString("mode"), "Updated Client ID: "+c.Param("id"))
		c.JSON(200, gin.H{"status": "success"})
	})
	v1.DELETE("/clients/:id", authMiddleware("clients"), func(c *gin.Context) {
		db.Exec("DELETE FROM nas WHERE id=?", c.Param("id"))
		logAudit(c.GetString("user"), c.GetString("mode"), "Deleted Client ID: "+c.Param("id"))
		c.JSON(200, gin.H{"status": "success"})
	})

	v1.GET("/admins", authMiddleware("admins"), func(c *gin.Context) {
		type AdminData struct {
			ID        int    `db:"id" json:"id"`
			Username  string `db:"username" json:"username"`
			Roles     string `db:"roles" json:"roles"`
			Has2FA    bool   `db:"has_2fa" json:"has_2fa"`
			HasAPIKey bool   `db:"has_api_key" json:"has_api_key"`
		}
		var res []AdminData
		db.Select(&res, "SELECT id, username, roles, totp_secret IS NOT NULL as has_2fa, api_key IS NOT NULL as has_api_key FROM api_admins ORDER BY id ASC")
		c.JSON(200, gin.H{"status": "success", "data": res})
	})
	v1.POST("/admins", authMiddleware("admins"), func(c *gin.Context) {
		var r struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			Roles     string `json:"roles"`
			Enable2FA bool   `json:"enable_2fa"`
		}
		c.BindJSON(&r)
		if strings.TrimSpace(r.Username) == "" || strings.TrimSpace(r.Password) == "" {
			c.JSON(400, gin.H{"detail": "Username and password required"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(r.Password), 10)
		var tsec *string
		uri := ""
		if r.Enable2FA {
			k, _ := totp.Generate(totp.GenerateOpts{Issuer: "FreeRADIUS", AccountName: r.Username})
			s := k.Secret()
			tsec = &s
			uri = k.URL()
		}
		db.Exec("INSERT INTO api_admins (username, password_hash, totp_secret, roles) VALUES (?, ?, ?, ?)", r.Username, hash, tsec, r.Roles)
		logAudit(c.GetString("user"), c.GetString("mode"), "Created Admin: "+r.Username)
		c.JSON(200, gin.H{"status": "success", "qr_uri": uri})
	})
	v1.PUT("/admins/:id", authMiddleware("admins"), func(c *gin.Context) {
		var r struct {
			Roles     string `json:"roles"`
			Enable2FA bool   `json:"enable_2fa"`
		}
		c.BindJSON(&r)
		id := c.Param("id")
		var admin struct {
			User string  `db:"username"`
			TOTP *string `db:"totp_secret"`
		}
		db.Get(&admin, "SELECT username, totp_secret FROM api_admins WHERE id=?", id)
		var tsec = admin.TOTP
		uri := ""
		if r.Enable2FA && tsec == nil {
			k, _ := totp.Generate(totp.GenerateOpts{Issuer: "FreeRADIUS", AccountName: admin.User})
			s := k.Secret()
			tsec = &s
			uri = k.URL()
		} else if !r.Enable2FA {
			tsec = nil
		}
		db.Exec("UPDATE api_admins SET roles=?, totp_secret=? WHERE id=?", r.Roles, tsec, id)
		logAudit(c.GetString("user"), c.GetString("mode"), "Updated Admin roles ID: "+id)
		c.JSON(200, gin.H{"status": "success", "qr_uri": uri})
	})
	v1.POST("/admins/:id/api-key", authMiddleware("admins"), func(c *gin.Context) {
		b := make([]byte, 16)
		rand.Read(b)
		key := hex.EncodeToString(b)
		db.Exec("UPDATE api_admins SET api_key=? WHERE id=?", key, c.Param("id"))
		logAudit(c.GetString("user"), c.GetString("mode"), "Generated API Key for Admin ID: "+c.Param("id"))
		c.JSON(200, gin.H{"status": "success", "api_key": key})
	})
	v1.DELETE("/admins/:id", authMiddleware("admins"), func(c *gin.Context) {
		db.Exec("DELETE FROM api_admins WHERE id=?", c.Param("id"))
		logAudit(c.GetString("user"), c.GetString("mode"), "Deleted Admin ID: "+c.Param("id"))
		c.JSON(200, gin.H{"status": "success"})
	})

	v1.GET("/audit", authMiddleware("audit"), func(c *gin.Context) {
		type AuditLog struct {
			ID        int        `db:"id" json:"id"`
			AdminUser string     `db:"admin_user" json:"admin_user"`
			Mode      string     `db:"mode" json:"mode"`
			Action    string     `db:"action" json:"action"`
			CreatedAt *time.Time `db:"created_at" json:"created_at"`
		}
		q := "SELECT id, admin_user, mode, action, created_at FROM api_audit WHERE 1=1"
		args := []interface{}{}
		if u := c.Query("user"); u != "" {
			q += " AND admin_user LIKE ?"
			args = append(args, "%"+u+"%")
		}
		if m := c.Query("mode"); m != "" {
			q += " AND mode = ?"
			args = append(args, m)
		}
		if a := c.Query("action"); a != "" {
			q += " AND action LIKE ?"
			args = append(args, "%"+a+"%")
		}
		if s := c.Query("start_date"); s != "" {
			q += " AND created_at >= ?"
			args = append(args, s+" 00:00:00")
		}
		if e := c.Query("end_date"); e != "" {
			q += " AND created_at <= ?"
			args = append(args, e+" 23:59:59")
		}
		var res []AuditLog
		db.Select(&res, q+" ORDER BY created_at DESC LIMIT 500", args...)
		c.JSON(200, gin.H{"status": "success", "data": res})
	})

	r.Run(":8000")
}
