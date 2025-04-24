all: bytetrace

bytetrace:
	cd build && ./build.sh $(CURDIR)

clean:
	cd build && rm bytetrace