/*
 * This file defines built-in restriction methods
 */

/*
 * No one
 */

Security.defineMethod("never", {
  fetch: [],
  transform: null,
  deny: function () {
    return true;
  }
});

/*
 * Logged In
 */

Security.defineMethod("ifLoggedIn", {
  fetch: [],
  transform: null,
  deny: function (type, arg, userId) {
    return !userId;
  }
});

/*
 * Specific User ID
 */

Security.defineMethod("ifHasUserId", {
  fetch: [],
  transform: null,
  deny: function (type, arg, userId) {
    return userId !== arg;
  }
});

/*
 * Specific Roles
 */

/*
 * alanning:roles support
 */
if (Package && Package["alanning:roles"]) {

  var Roles = Package["alanning:roles"].Roles;

  Security.defineMethod("ifHasRole", {
    fetch: [],
    transform: null,
    deny: function (type, arg, userId) {
      if (!arg) {
        throw new Error('ifHasRole security rule method requires an argument');
      }
      if (arg.role) {
        return !Roles.userIsInRole(userId, arg.role, arg.group);
      } else {
        return !Roles.userIsInRole(userId, arg);
      }
    }
  });

}

/*
 * nicolaslopezj:roles support
 * Note: doesn't support groups
 */
if (Package && Package["nicolaslopezj:roles"]) {

  var Roles = Package["nicolaslopezj:roles"].Roles;

  Security.defineMethod("ifHasRole", {
    fetch: [],
    transform: null,
    deny: function (type, arg, userId) {
      if (!arg) {
        throw new Error('ifHasRole security rule method requires an argument');
      }
      return !Roles.userHasRole(userId, arg);
    }
  });

}

/*
 *  FSystem Integration
 *  added by Fuat Sengul
 *  This is intentionally not a package
*/

if(typeof FSystem != undefined){
  Security.defineMethod('isAllowedForFunction', {
    fetch: [],
    transform: null,
    deny: function (type, arg, userId) {
      if (!arg) {
        throw new Error('ifHasRole security rule method requires an argument');
      }
      var _user = Meteor.users.findOne(userId);
      return !FSystem.IsAllowedForFunction(_user, arg);
    } 
  });
}

/*
 * Specific Properties
 */

Security.defineMethod("onlyProps", {
  fetch: [],
  transform: null,
  deny: function (type, arg, userId, doc, fieldNames) {
    if (!_.isArray(arg)) {
      arg = [arg];
    }

    fieldNames = fieldNames || _.keys(doc);

    return !_.every(fieldNames, function (fieldName) {
      return _.contains(arg, fieldName);
    });
  }
});

Security.defineMethod("exceptProps", {
  fetch: [],
  transform: null,
  deny: function (type, arg, userId, doc, fieldNames) {
    if (!_.isArray(arg)) {
      arg = [arg];
    }

    fieldNames = fieldNames || _.keys(doc);

    return _.any(fieldNames, function (fieldName) {
      return _.contains(arg, fieldName);
    });
  }
});
