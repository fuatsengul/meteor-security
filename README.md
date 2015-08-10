fuatsengul:security
=========================
This package will be a part of the ultimate security and user management pack fuatsengul:user-management.

The user-management package is not ready yet, and will only support for semantic-ui for start. It will have very simple UIs, also role definitions.
 


A Meteor package that provides a simple, logical, plain language API for defining write security on your MongoDB collections. Wraps the core allow/deny security.

## Installation

```bash
$ meteor add ongoworks:security
```

## Why?

There are two main problems that this package solves.

### Allow Functions Don't Provide Reliable Security

Most Meteor developers should be familiar with the standard `allow` and `deny` functions that can be used to secure database operations that originate on the client. But most developers handle security by simply defining a few `allow` functions. This may work in most cases, but many people don't realize that only *one* allow function needs to return true and then the rest of them aren't even called. If you use a lot of community packages in your app, there is the possibility that one of them will add an `allow` function that returns `true` for a perfectly good reason, but if you are not aware of it, you may not even realize that your `allow` function is never being called, and your security logic is not being applied.

*This package takes `allow` functions out of the equation and handles all security through `deny` functions, which are guaranteed to be called.*

### A File Full of Allow/Deny Functions Is Not Easy To Read

When you come back to a project after some time or begin helping with a project you did not create, it may be difficult to read through allow/deny rules and try to figure out what they are doing. By encapsulating security logic in a readable string, it becomes much easier to skim your applied rules and understand what you might need to change or fix.

*This package assign readable names to rule methods, making it easier to skim and see what security is applied to which collections.*

## How It Works

Instead of calling `allow` or `deny` on your collections, call `permit` to begin a new rule chain. Then optionally call one or more restriction methods. When you've defined the entire rule, call `apply`. Here are some examples:

*/server/security.js:*

```js
// Any client may insert, update, or remove a post without restriction
Posts.permit(['insert', 'update', 'remove']).apply();

// No clients may insert, update, or remove posts
Posts.permit(['insert', 'update', 'remove']).never().apply();

// Clients may insert posts only if a user is logged in
Posts.permit('insert').ifLoggedIn().apply();

// Clients may remove posts only if an admin user is logged in
Posts.permit('remove').ifHasRole('admin').apply();

// Admin users may update any properties of any post, but regular users may
// update posts only if they don't try to change the `author` or `date` properties
Posts.permit('update').ifHasRole('admin').apply();
Posts.permit('update').ifLoggedIn().exceptProps(['author', 'date']).apply();

//FSystem Integration
Posts.permit('update').isAllowedForFunction('updatePosts').apply();


```

## Built-In Rule Chain Methods

* **never()** - Prevents the database operations from untrusted code. Should be the same as not defining any rules, but it never hurts to be extra careful.
* **ifLoggedIn()** - Allows the database operations from untrusted code only when there is a logged in user.
* **ifHasUserId(userId)** - Allows the database operations from untrusted code only for the given user.
* **ifHasRole(role)** - Allows the database operations from untrusted code only for users with the given role. Using this method requires adding the `alanning:roles` package to your app. If you use role groups, an alternative syntax is `ifHasRole({role: role, group: group})`
* **onlyProps(props)** - Allows the database operations from untrusted code for the given top-level doc properties only. `props` can be a string or an array of strings.
* **exceptProps(props)** - Allows the database operations from untrusted code for all top-level doc properties except those specified. `props` can be a string or an array of strings.

## API

*Note: This entire API and all rule methods are available only in server code. As a security best practice, you should not define your security rules in client code or in server code that is sent to clients. Meteor allow/deny functions are documented as server-only functions, although they are currently available in client code, too.*

### Security.permit(types)

If you want to apply the same rule to multiple collections at once, you can do

```js
Security.permit(['insert', 'update']).collections([Collection1, Collection2])...ruleChainMethods()...apply();
```

which is equivalent to

```js
Collection1.permit(['insert', 'update'])...ruleChainMethods()...apply();
Collection2.permit(['insert', 'update'])...ruleChainMethods()...apply();
```

### Security.defineMethod(name, definition)

Call `Security.defineMethod` to define a method that may be used in the rule chain to restrict the current rule. Pass a `definition` argument, which must contain a `deny` property set to a `deny` function for that rule. The `deny` function is the same as the standard Meteor one, except that it receives a `type` string as its first argument and the second argument is whatever the user passes to your method when calling it. The full function signature for inserts and removes is `(type, arg, userId, doc)` and for updates is `(type, arg, userId, doc, fields, modifier)`.

As an example, here is the definition for the built-in `ifHasUserId` method:

```js
Security.defineMethod("ifHasUserId", {
  fetch: [],
  transform: null,
  deny: function (type, arg, userId) {
    return userId !== arg;
  }
});
```

And here's an example of using the `doc` property to create a method that can be used with `Meteor.users` to check whether it's the current user's document:

```js
Security.defineMethod("ifIsCurrentUser", {
  fetch: [],
  transform: null,
  deny: function (type, arg, userId, doc) {
    return userId !== doc._id;
  }
});
```

#### Transformations

If a rule is applied to a collection and that collection has a `transform` function, the `doc` received by your rule's deny function will be transformed. In most cases, you will want to prevent this by adding `transform: null` to your rule definition. Alternatively, you can set `transform` to a function in your rule definition, and that transformation will be run before calling the deny function.

#### Fetch

It's good practice to include `fetch: []` in your rule definition, listing any fields you need for your deny logic. However, the `fetch` option is not yet implemented. Currently all fields are fetched.

### Security.Rule

An object of this type is returned throughout the rule chain.

## Details

* Simply adding this package to your app does not affect your app security in any way. Only calling `apply` on a rule chain for a collection will affect your app security.
* If you have not defined any rules for a collection, nothing is allowed (assuming you have removed the `insecure` package).
* It is fine and often necessary to apply more than one rule to the same collection. Each rule is evaluated separately, and at least one must pass.
* You can mix 'n' match these rules with normal `allow/deny` functions, but keep in mind that your `allow` functions may have no effect if you've called Security `apply` for the same collection.
* If you want to use this with the Meteor.users collections, use the Security.permit() syntax. Working example:

    Security.permit(['insert', 'update', 'remove']).collections([
        Meteor.users
    ]).never().apply();

## Logic

Rules within the same chain combine with AND. Multiple chains for the same collection combine with OR. In other words, at least one chain of rules must pass for the collection-operation combination. They are evaluated in the order they are defined. As soon as one passes for the collection-operation, no more are tested.

For example:

```js
// You can remove a post if you have admin role
Posts.permit('remove').ifHasRole('admin').apply();
// OR You can remove a post if you are logged in AND you created it AND it is not a Friday
Posts.permit('remove').ifLoggedIn().ifCreated().ifNotFriday().apply();
// If neither of the above are true, the default behavior is to deny removal
```

## Using with CollectionFS

This package supports the special "download" allow/deny for the CollectionFS packages. You must use the underlying collection of your `FS.Collection` instances, which is referenced by the `files` object. For example:

```js
Images.files.permit(['insert', 'update', 'remove']).ifHasRole('admin').apply();
Images.files.permit(['download']).ifLoggedIn().apply();
```

## Contributing

You are welcome to submit pull requests if you have ideas for fixing or improving the API. If you come up with generally useful security rules, you should publish your own package that depends on this one and document the rules it provides so that others can use them. You may then submit a pull request to add a link to your package documentation in this readme.
