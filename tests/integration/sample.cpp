// Small C++ program used by tests/integration/run.sh. Built twice: as-is ("v1") and with
// -DV2, which adds/changes code so addresses and bodies shift between the builds.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define NOINLINE __attribute__((noinline))

struct Config {
    int verbosity;
    int retries;
    const char *name;
#ifdef V2
    int timeout_ms;
#endif
};

Config g_config = {1, 3, "default"};
int g_counter = 0;

class Shape {
public:
    virtual ~Shape() {}
    virtual double area() const = 0;
    virtual const char *kind() const { return "shape"; }
    virtual void describe() const { std::printf("A %s with area %.2f\n", kind(), area()); }
};

class Rect : public Shape {
public:
    Rect(double w, double h) : w_(w), h_(h) {}
    double area() const override { return w_ * h_; }
    const char *kind() const override { return "rectangle"; }
private:
    double w_, h_;
};

class Circle : public Shape {
public:
    explicit Circle(double r) : r_(r) {}
    double area() const override { return 3.14159 * r_ * r_; }
    const char *kind() const override { return "circle"; }
    void describe() const override { std::printf("Circle of radius %.2f\n", r_); }
private:
    double r_;
};

NOINLINE int parse_verbosity(const char *arg) {
    if (std::strcmp(arg, "--quiet") == 0) return 0;
    if (std::strcmp(arg, "--verbose") == 0) return 2;
#ifdef V2
    if (std::strcmp(arg, "--debug") == 0) return 3;
#endif
    return 1;
}

NOINLINE int checksum(const char *s) {
    int h = 5381;
    while (*s) h = h * 33 + *s++;
    return h;
}

NOINLINE void log_message(int level, const char *msg) {
    if (level <= g_config.verbosity) std::fprintf(stderr, "[log] %s\n", msg);
    g_counter++;
}

NOINLINE int retry_operation(int (*op)(int), int arg) {
    for (int i = 0; i < g_config.retries; i++) {
        int r = op(arg);
        if (r >= 0) return r;
        log_message(2, "operation failed, retrying");
    }
    return -1;
}

NOINLINE int flaky_op(int x) { return (x + g_counter) % 3 == 0 ? x : -1; }

#ifdef V2
NOINLINE void print_banner() { std::printf("sample tool v2 - now with banners\n"); }
#endif

NOINLINE Shape *make_shape(int which) {
    if (which == 0) return new Rect(2.0, 3.0);
    return new Circle(1.5);
}

NOINLINE void process_shapes(int n) {
    for (int i = 0; i < n; i++) {
        Shape *s = make_shape(i % 2);
        s->describe();
        delete s;
    }
}

int main(int argc, char **argv) {
#ifdef V2
    print_banner();
#endif
    for (int i = 1; i < argc; i++) g_config.verbosity = parse_verbosity(argv[i]);
    log_message(1, "starting up");
    std::printf("config %s checksum %d\n", g_config.name, checksum(g_config.name));
    int r = retry_operation(flaky_op, argc);
    if (r < 0) {
        log_message(0, "giving up");
        return EXIT_FAILURE;
    }
    process_shapes(argc + 1);
    log_message(1, "done");
    return EXIT_SUCCESS;
}
