build-test:
	gcc -o test test.c

build:
	go mod tidy && go generate && go build -o uprobe

run:
	./uprobe

run-test:
	./test



