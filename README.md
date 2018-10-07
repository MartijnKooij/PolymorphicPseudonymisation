​
[![Build Status](https://martijnkooij.visualstudio.com/Polymorphic%20Pseudonymisation/_apis/build/status/PolymorphicPseudonymisation)](https://martijnkooij.visualstudio.com/Polymorphic%20Pseudonymisation/_build/latest?definitionId=9)

## Polymorphic Pseudonymisation in C#
.Net Standard C# implementation of Polymorphic Pseudonymisation Decryption

# Table of Contents
1. [About the project](#about-the-project)
2. [Installation](#installation)
   * [Step 1: Installing the project](#step-1-installing-the-project)
   * [Step 2: Converting to PEM](#step-2-converting-to-pem)
      * [Commands to convert the p7 and p8 files to PEM](#commands-to-convert-the-p7-and-p8-files-to-pem)
   * [Step 3: Registering the service](#step-3-registering-the-service)
3. [Usage](#usage)
4. [Contribute](#contribute)
5. [License](#license)


## About the project

This is a C# port of the work done by [Bram van Pelt](https://www.linkedin.com/in/bram-van-pelt) who developed the Java implementation of this decryption algorithm. You can find the original Java project by Bram in [PPDecryption](https://github.com/BramvanPelt/PPDecryption/)

Polymorphic pseudonymisation is an encryption technology developed by [Eric Verheul](http://www.cs.ru.nl/E.Verheul/) to ensure the privacy and security of users in an authentication system. This technology has been incorporated in the Dutch "EID" system. Polymorphic pseudonymisation is based on the El-Ghamal encryption system and split proof evidence.

For more information on the El-Ghamal crypto system: http://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf

For more information on Polymorphic pseudonymisation: http://www.cs.ru.nl/E.Verheul/papers/PP2/PEKScheme.pdf

## Installation
*This part is still work in progress as I still need to add NuGet installation support*

#### Step 1: Installing the project
For now you need to either clone the repository and reference the project or build it locally and reference the output dll. I am working on a NuGet package for this

#### Step 2: Converting to PEM
From the BSNk registrar you will receive 3 sets of p7 and p8 files. 1 set for decrypting the identity, and 2 sets for decrypting the pseudonym.

Since the actual decrypting of the data is done using PEM we need to convert these files to PEM using openssl. For Windows users an easy and relatively safe place to get openssl from is from the Git for Windows client located in: c:\Program Files\Git\usr\bin\ (if you have installed it)

##### Commands to convert the p7 and p8 files to PEM
`openssl cms -decrypt -inform der -in dv_keys_ID_D_oin.p7 -inkey privatep8.key -out id.pem`

`openssl cms -decrypt -inform der -in dv_keys_PC_D_oin.p7 -inkey privatep8.key -out pc.pem`

`openssl cms -decrypt -inform der -in dv_keys_PD_D_oin.p7 -inkey privatep8.key -out pd.pem`

You will also receive an IdentityPoint and PseudonymPoint which you also need to setup the service in step 3.

#### Step 3: Registering the service

To use this library in your application you can register the service with it's decryption options in your application startup's ConfigureServices method.

```csharp
services.AddDecryptService(options =>
    {
        options.IdentityPem = File.ReadAllText("path/to/id4.pem");
        options.IdentityPoint = "AmUppru04ghsI/FvbvV59eoX3lCUWlMAZKu1pPdlvixch5avV+aFwQg=";
        options.PseudoKeyPem = File.ReadAllText("path/to/pd4.pem");
        options.PseudoClosingKeyPem = File.ReadAllText("path/to/pc.pem");
        options.PseudonymPoint = "A9GtKDUn++nl2NWtN4F/2id1gmBhxn4I6Qr9BfeMN+fjNuXGvE79qHc=";
    });
```

If you are not using the dotnet core dependency injection or perhaps not even a web application at all you can create an instance of the `DecryptService` itself.

## Usage

After setting the service up you can call it's 2 public methods passing them the encrypted identity or pseudonym and it will decrypt them for you.
```csharp
var decryptedBsn = decryptService.GetIdentity(encryptedIdentity);
var decryptedPseudonym = decryptService.GetPseudonym(encryptedPseudonym);

```

## Contribute

You can contribute to this project by forking the repository and make your contribution to the fork.
After that you can open a pull request to initiate a discussion around the contribution.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details