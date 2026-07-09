CC = gcc
CFLAGS = -O3 -Wall -Wextra
LIBS = -lpcap
TARGET = razor_blade
OBJ = main.o io_utils.o network.o parser.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
