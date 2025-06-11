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

int power(int a, int n) {
	int product = 1;
	for (int i = 0; i<n; i++) {
		product *= a;
	}
	return product;
}

int div(int a, int b, int* q) {
	if (b != 0) {
		*q = a/b;
		return 0;
	} else {
		return 1;
	}
}

int rsh(int a, int n) {
	int result = 0;
	div(a, power(2, n), &result);
	return result;
}

int sum(int* a, unsigned int n) {
	int sum = 0;
	for (int i = 0; i < n; i++) {
		sum += a[i];
	}
	return sum;
}
