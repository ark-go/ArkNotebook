SHELL := /bin/bash
arklibgo := ~/ProjectsGo/arkAlias.sh
version = ~/ProjectsGo/arkAlias.sh getlastversion
PROJECTNAME=$(shell basename `pwd`)
#.PHONY: check

.SILENT: server serverwin

server:
	@echo $$($(version))
	$(info +Компиляция Linux)
	go build -ldflags "-s -w -X 'main.versionProg=$$($(version))'" -o ./bin/main/$(PROJECTNAME) main/main.go
	sudo ./bin/main/$(PROJECTNAME)

serverwin:
	$(info +Компиляция windows)
	GOOS=windows GOARCH=amd64 go build -o ./bin/main/$(PROJECTNAME).exe -tags static -ldflags "-s -w -X 'main.versionProg=$$($(version))'" main/main.go
