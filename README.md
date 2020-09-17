# apple-signin
Apple ID signin with Java

This library can help in the Java server side handling of the [Sign in with Apple ID.](https://developer.apple.com/sign-in-with-apple/)

Clients (web or mobile) can initiate the Apple ID signup/login process and send the received info to the Java server. Using this library you can validate the info received from the clients through Apple servers. This won't just validate that the client authenticated by Apple, but will also identify the user by an Apple user ID or by an email/name (received only for the first time).

### Download

Download the library from maven:
```xml
<dependency>
  <groupId>com.github.mikereem</groupId>
  <artifactId>apple-signin</artifactId>
  <version>1.0</version>
</dependency>
```
### Initialization

You have to initialize the `AppleSigninUtil` before you could use it. For this, you will need the Key ID and Team ID from Apple. You can get this from [Apple Developer](https://developer.apple.com). Also you will need your private keytore file (.p8).
```java
private AppleSigninUtil appleSignin;

public void init() {
  appleSignin = new AppleSigninUtil();
  try {
    appleSignin.init("Your Apple Key ID", "Your Apple Team ID", new InputStreamReader(
      getClass().getClassLoader().getResourceAsStream("META-INF/AuthKey_yourprivatekey.p8")));
  } catch (IOException e) {
    LOGGER.error("Error during Apple Signin Util initialization", e);
  }
}
```

### Example 1: Sign up using Apple ID

When a client application does the initial authentication by Apple ID, Apple will return with an `identityToken` and an `authorizationCode`. Additionally to this, it will return the email, firstname and last name only once. It is your responsibility to store those info, because later it won't be provided by Apple.

If the authentication is done by a mobile client, then it should send the `identityToken` and `authorizationCode` to the server for validation. Additionally to that, it should send the received user info, so the server will be able to finish the registration. In this case the server should just validate if the client was really authenticated to Apple:

```java
Claims claims = null;
try {
  claims = appleSignin.authorize(clientId, identityToken, authorizationCode, null);
  if (claims != null) {
    LOGGER.info("Apple authentication validated for user " + appleSignin.getEmail(claims));
  }
} catch (Throwable t) {
  LOGGER.error("Error during apple authorization validation of mobile registration", t);
}
```

For the validation you have to use the `authorize` method of the `AppleSigninUtil`. This needs a clientId: every client (webclient, mobile app) should have one. It returns a JWT Claims object if all information was valid. This claims can be later used to get information about the user, using the `AppleSigninUtil` (for example `appleSignin.getEmail(claims)`).

If the authentication is done by a webclient, then the answer from Apple can be requested to the Java server directly. In this case you can not just validate the client's request, but also your code will receive the user object from Apple, because this will be the first authentication.

```java
String userJson = req.getParameter("user");
Claims claims = null;
try {
  claims = appleSignin.authorize(clientId, identityToken, authorizationCode, null);
  if (claims != null) {
    LOGGER.info("Apple authentication validated for user " + appleSignin.getEmail(claims));
    User user = null;
    if (userJson != null) {
      user = appleSignin.parseUser(userJson);
      LOGGER.info("User received:" + user);
    }
  }
} catch (Throwable t) {
  LOGGER.error("Error during apple authorization validation of mobile registration", t);
}
```

In this case apple will send a `user` parameter in the request, which is a JSON. Using the `AppleSigninUtil.parseUser` it is possible to parse this JSON and get out the initial user info and finish the registration process.

### Example 2: Login with Apple ID

For Apple, there is no difference between signup and login. It is just an authentication, but of course you should not expect to receive a user object in this case.

```java
Claims claims = null;
try {
  claims = appleSignin.authorize(clientId, identityToken, authorizationCode, null);
  if (claims != null) {
    LOGGER.info("Apple authentication validated for user " + appleSignin.getSubject(claims));
  }
} catch (Throwable t) {
  LOGGER.error("Error during apple authorization validation of mobile registration", t);
}
```

It is a good idea to connect your user implementation to Apple's user ID, which can be read after a successful authentication from the Claims object using the `AppleSigninUtil.getSubject` method.
