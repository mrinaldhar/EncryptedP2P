#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define SIZE 1000	
#define ITER 100


int MillerRabin(long long int , long long int);
typedef union {
	struct{
		long long int n;
		long long int e;
	} public_key;
	
	struct{
		long long int n;
		long long int d;

	} private_key;
} key_pair;



long long int gcd(long long int a, long long int b){
	if(a<0)
		a=-a;
	if(b<0)
		b=-b;
	if(b==0)
		return a;
	return gcd(b, a%b);
}

long long int mod_inverse(long long int a, long long int n){
	int t=0;
	int r=n;
	int new_t=1;
	int new_r=a;
	int q;
	int temp;
	while(new_r!=0){
		q=r/new_r;
		
		temp=t;
		t=new_t;
		new_t=temp-q*new_t;
	
		temp=r;
		r=new_r;
		new_r=temp-q*new_r;
	}	
	
	if(r>1)
		printf("Inverse does not exist.\n");
	else if(t<0)
		t=t+n;
	return t;
}


long long int fast_power(long long int x, long long int e, long long int n){             //Binary Exponentiation
	if(n==1)
		return 0;
	x=x%n;
	long long int res = 1;
	while(e>0){
		if(e%2!=0)
			res = (res*x)%n;
		e = e >> 1;
		x = (x*x)%n;
	}
	return res;
}

int confirm_prime(long long int n){
	long long int i;
	int flag=0;
	for(i=2;i <= ((long long int)sqrt(n))+1;i++){
		if(n%i==0)
			flag=1;
	}

	if(flag==0)
		return 1;
	else
		return 0;
}

void KeyGen(key_pair* pub, key_pair* priv){
	long long int n, p=6, q=8, enc, dec, phi;

	//Calculating p
	while(1){
		srand((unsigned int)time(NULL));
		p=rand()%SIZE;
		if(p%2==0)
			continue;
		if(MillerRabin(p, ITER))
			break;
	}

	//Calculating q
	while(1){
		srand((unsigned int)time(NULL));
		q=rand()%SIZE;
		if(q%2==0 || q==p)
			continue;

		if(MillerRabin(q, ITER))
			break;
	}
	
	//Calculate n and phi
	if(confirm_prime(p)==1 && confirm_prime(q)==1)
		n=p*q;
	else{
		printf("KeyGen failed. Please try again.\n");
		exit(1);
	}	

	phi = (p-1) * (q-1);
	
	//Calculate enc
	while(1){
		srand((unsigned int)time(NULL));
		enc=rand()%phi;
		if(gcd(enc, phi)==1)
			break;
	}
	
	//Calculate dec
	dec = mod_inverse(enc, phi);
 
	pub->public_key.n = n;
	pub->public_key.e = enc;
	priv->private_key.n = n;
	priv->private_key.d = dec;
}


int MillerRabin(long long int n,long long int iteration) {
	long long int m, t, a, u;
	long long int i, j, flag;
	if(n%2 == 0)
		return 0; 
	m = (n-1)/2;
	t = 1;

	while( m % 2 == 0){
		m = m/2;
		t = t + 1;
	}
	for (j=0; j < iteration; j++) { 
		flag=0;
		srand((unsigned int) time(NULL));
		a = rand()%n + 1; 
		u = fast_power(a,m,n);
		if (u == 1 || u == n - 1)
			flag = 1; 
		for(i=0;i<t;i++) {
			if(u == n - 1) 
				flag = 1;
			u = (u * u) % n;
		}
		if( flag == 0 )
			return 0; 
	}
	return 1;
}

long long int Encryption(long long int mess, key_pair pub){
	return fast_power(mess, pub.public_key.e, pub.public_key.n);

}

long long int Decryption(long long int ciph, key_pair priv){
	return fast_power(ciph, priv.private_key.d, priv.private_key.n);
}
