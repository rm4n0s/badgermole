package main

import (
	"html/template"
	"io"
	"log"
)

type Template struct {
	tmpl *template.Template
}

func NewTemplate() *Template {
	g, err := template.ParseGlob("templates/**/*.html")
	if err != nil {
		log.Fatal(err)
	}
	return &Template{
		tmpl: template.Must(g, err),
	}
}

func (t *Template) Render(w io.Writer, name string, data interface{}) error {
	return t.tmpl.ExecuteTemplate(w, name, data)
}
