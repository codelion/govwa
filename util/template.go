package util

import (
	"log"
	"net/http"
	"encoding/json"
	"html/template"

	"github.com/govwa/user/session"
)

func SafeRender(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {

	s := session.New()
	sid := s.GetSession(r, "id")//make uid available to all page
	data["uid"] = sid

	tmpl := template.Must(template.ParseGlob("templates/*"))
	err := tmpl.ExecuteTemplate(w, name, data)
	if err != nil{
		log.Println(err.Error())
	}
}

func RenderAsJson(w http.ResponseWriter, data ...interface{}) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

// Note: Removed UnSafeRender and ToHTML functions because using direct HTML without encoding is risky.
// Instead, use SafeRender with properly sanitized input data.
