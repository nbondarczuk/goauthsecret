TARGET = goauthsecret

build:
	go build -o $(TARGET) *.go

clean:
	go clean
	rm -f $(TARGET)
	find . -name "*~" -exec rm -f {} \;

