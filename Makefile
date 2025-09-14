CC=x86_64-w64-mingw32-gcc

SRC=veeam-backoops.c
OUT=veeam-backoops-x86_64
OUT_STRIPPED=$(OUT)-stripped

LFLAGS=-lcrypt32
FLAGS=-Wall -Wextra -Wno-cast-function-type -Wno-format-truncation
STRIPPED_FLAGS=-s

all:
	$(CC) $(SRC) -o $(OUT) $(FLAGS) $(LFLAGS)
	$(CC) $(SRC) -o $(OUT_STRIPPED) $(FLAGS) $(STRIPPED_FLAGS) $(LFLAGS)
clean:
	rm $(OUT).exe
	rm $(OUT_STRIPPED).exe
