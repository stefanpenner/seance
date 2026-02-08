.PHONY: build run clean

build:
	go build -o seance .

run: build
	@if [ -z "$$SEANCE_PASSWORD" ]; then echo "SEANCE_PASSWORD is required"; exit 1; fi
	./seance

clean:
	rm -f seance
