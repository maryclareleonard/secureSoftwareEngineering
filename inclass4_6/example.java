class A {
    function() {}
}
class B extends A {
    function() {}
}
class C extends B {
    function() {}
}
class D extends B {
    function() {}
}


static void main () {
    B b1 = new B();
    A a1 = new A();

    mainf1(b1);
    mainf2(b1);
}
static void mainf1 (A aInstance) {
    aInstance.function();
}
static void mainf2 (B bInstance) {
    B bInstanceLocal = bInstance;
    b3 = new C();
    b3.function();
}