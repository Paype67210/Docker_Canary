C++	=	g++
CFLAGS	=	-g -Wall -Wextra -std=c++17 -Iinclude
LDFLAGS	=
SRC = &(wildcard *.cpp scanner/*.cpp utils/*.cpp)
OBJ = $(SRC:.cpp=.o)

analyzer: $(OBJ)
	$(C++) $(LDFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete."

clean:
	rm -f analyzer *.o scanner/*.o utils/*.o
	@echo "Clean complete."

fclean: clean
	rm -f $(OBJ) analyzer
	@echo "Full clean complete."

.PHONY: all clean fclean
