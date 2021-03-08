# Scrypt Password Hasher for ASP.NET Core Identity

[![NuGet](https://img.shields.io/nuget/v/ScottBrady91.AspNetCore.Identity.ScryptPasswordHasher.svg)](https://www.nuget.org/packages/ScottBrady91.AspNetCore.Identity.ScryptPasswordHasher/)

An implementation of IPasswordHasher<TUser> using [Scrypt.NET](https://github.com/viniciuschiele/Scrypt).

## Installation

```csharp
services.AddIdentity<TUser, TRole>();
services.AddScoped<IPasswordHasher<TUser>, ScryptPasswordHasher<TUser>>();
```

### Options

- **IterationCount**: int
- **BlockSize**: int
- **ThreadCount**: int

Register with:

```csharp
services.Configure<ScryptPasswordHasherOptions>(options => {
    options.IterationCount = 16384;
    options.BlockSize = 8;
    options.ThreadCount = 1;
});
```

## .NET Support

This library supports Current and LTS versions of .NET.
