all: bytetrace

bytetrace:
	cd build && ./build.sh $(CURDIR) amd64

arm64:
	cd build && ./build.sh $(CURDIR) arm64

clean:
	cd build && rm bytetrace