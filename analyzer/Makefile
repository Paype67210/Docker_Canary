C++	=	g++
CFLAGS	=	-g3 -Wall -Wextra -Werror -std=c++17 -Iinclude
LDFLAGS	=
SRC = $(wildcard *.cpp scanner/*.cpp utils/*.cpp report/*.cpp)
OBJ = $(SRC:.cpp=.o)
TARGET = analyzer

# Règle principale
all: $(TARGET)

$(TARGET): $(OBJ)
	$(C++) $(LDFLAGS) $(CFLAGS) -o $@ $^
	@echo "Building complete."

clean:
	rm -f $(OBJ)
	@echo "Clean complete."

fclean: clean
	rm -f $(TARGET)
	@echo "Full clean complete."

re: fclean all
	@echo "Rebuild complete."

.PHONY: all clean fclean re
