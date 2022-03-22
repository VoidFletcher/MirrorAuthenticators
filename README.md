# MirrorAuthenticators
A repository containing authenticators for Mirror Networking, provided along with my book on Creating Multiplayer Games in Unity Using Mirror Networking. 
This repository will continue to grow as I build additional authenticators for Mirror Networking.  

Currently, the repository supports the following authenticator(s):
- Windows Google Authenticator  

## IMPORTANT
As of somewhere in Unity 2020.3.x, Unity has included their own newtonsoft dll. Ensure that you are on the correct version by completing the following steps:
1) Remove the Unity **Version Control** package, as this has a dependency to an old version of newtonsoft, this might get fixed in future.
2) Install the latest Unity version of newtonsoft by adding the following package via github url: **com.unity.nuget.newtonsoft-json**

## Dependencies
This repository is updated to match the following versions:

**Unity 2020.3.31f1**  
**Mirror v65**

## IMPORTANT - Book Readers
Google now requires HTTPS for your scope definitions, please add https://www.google...etc for your scope definitions or you will get an error back from the API.
