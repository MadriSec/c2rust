int add(int a, int b) {
	return a + b;
}

int mul(int a, int b) {
	int sum = 0;
	for (int i = 0; i < b; i++) {
		sum += a;
	}
	return sum;
}
