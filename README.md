# Scrypt Password Hasher for ASP.NET Core Identity (ASP.NET Identity 3)

An implementation of IPasswordHasher<TUser> using [Scrypt.NET](https://github.com/viniciuschiele/Scrypt).

## Installation

```
services.AddScoped<IPasswordHasher<ApplicationUser>, ScryptPasswordHasher<ApplicationUser>>();
```

### Options

 - **IterationCount**: int
 - **BlockSize**: int
 - **ThreadCount**: int

Register with:
```
services.Configure<ScryptPasswordHasherOptions>(options => {
	options.IterationCount = 16384;
	options.BlockSize = 8;
	options.ThreadCount = 1;
});
```
