#include <cstdlib>
#include <iostream>

class N {
public:
    N(int value) {
        this->value = value;
    }

    void setAnnotation(char* annotation) {
        this->annotation = annotation;
    }

    void print() {
        std::cout << "Value: " << value << ", Annotation: " << annotation << std::endl;
    }

private:
    int value;
    char* annotation;
};

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        std::exit(1);
    }

    N* n1 = new N(5);
    N* n2 = new N(6);

    n1->setAnnotation(argv[1]);
    n2->print();
    n1->print();

    return 0;
}

