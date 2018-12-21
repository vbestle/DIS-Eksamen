package controllers;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sun.tools.doclets.formats.html.SourceToHTMLConverter;
import model.User;
import utils.Hashing;
import utils.Log;

import javax.sound.midi.Soundbank;

public class UserController {

  private static DatabaseController dbCon;

  public UserController() {
    dbCon = new DatabaseController();
  }

  //hashing initialiseres
  public static Hashing hashing = new Hashing();

  public static User getUser(int id) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where id=" + id;

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"));

        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  /**
   * Get all users in database
   *
   * @return
   */
  public static ArrayList<User> getUsers() {

    // Check for DB connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build SQL
    String sql = "SELECT * FROM user";

    // Do the query and initialyze an empty list for use if we don't get results
    ResultSet rs = dbCon.query(sql);
    ArrayList<User> users = new ArrayList<User>();

    try {
      // Loop through DB Data
      while (rs.next()) {
        User user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"));

        // Add element to list
        users.add(user);
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return the list of users
    return users;
  }



  public static User createUser(User user) {

    // Write in log that we've reach this step
    Log.writeLog(UserController.class.getName(), user, "Actually creating a user in DB", 0);

    // Set creation time for user.
    user.setCreatedTime(System.currentTimeMillis() / 1000L);

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Insert the user in the DB
    // TODO: Hash the user password before saving it. (FIX)
    int userID = dbCon.insert(
            "INSERT INTO user(first_name, last_name, password, email, created_at) VALUES('"
                    + user.getFirstname()
                    + "', '"
                    + user.getLastname()
                    + "', '"
                    + hashing.saltingSha(user.getPassword()) //hash tilføjet
                    + "', '"
                    + user.getEmail()
                    + "', "
                    + user.getCreatedTime()
                    + ")");

    if (userID != 0) {
      //Update the userid of the user before returning
      user.setId(userID);
    } else {
      // Return null if user has not been inserted into database
      return null;
    }

    // Return user
    return user;
  }


  // Delete User metode
  public static boolean deleteUser(String token) {


    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    DecodedJWT jwt = null;
    try {
      Algorithm algorithm = Algorithm.HMAC256("secret");
      JWTVerifier verifier = JWT.require(algorithm)
              .build();
      jwt = verifier.verify(token);
    }catch (JWTVerificationException e) {
    }


    // Delete the user from the DB
    String sql = "DELETE FROM user WHERE id=" + jwt.getClaim("userid").asInt();

    return dbCon.updateOrDeleteUser(sql);

  }


//Update User metode

  public static User updateUser(User updatedUser) {

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    DecodedJWT jwt = null;
    try{
      jwt = JWT.decode(updatedUser.getToken());
    } catch (JWTDecodeException eJWT) {

    }
    int id = jwt.getClaim("userid").asInt();

    User userToUpdate = UserController.getUser(id);

    if (updatedUser.getFirstname() == null) {
      updatedUser.setFirstname(userToUpdate.getFirstname());
    }
    if (updatedUser.getLastname() == null) {
      updatedUser.setLastname(userToUpdate.getLastname());
    }
    if (updatedUser.getEmail() == null) {
      updatedUser.setEmail(userToUpdate.getEmail());
    }
    if (updatedUser.getPassword() == null) {
      updatedUser.setPassword(userToUpdate.getPassword());
    }


    String sql =
            "UPDATE user SET first_name = ,'" + updatedUser.getFirstname() +
            "'last_name = ,'" + updatedUser.getLastname() +
            "'password = ,'" + hashing.saltingSha(updatedUser.getPassword()) +
            "'email = ,'" + updatedUser.getEmail() +
            "'WHERE id='" + jwt.getClaim("userid").asInt();


     if(dbCon.updateOrDeleteUser(sql)){
       return updatedUser;
    }

    return null;


    }


  //Authorize User metode til login

  public static User authorizeUser(String loginEmail) {

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }
      String sql = "SELECT * FROM user where email='" + loginEmail + "'";

      //Kører SQL query
      ResultSet resultSet = dbCon.query(sql);
      User user = null;

      //Henter objektet af User
      try {
        if (resultSet.next()) {
          user = new User(
                  resultSet.getInt("id"),
                  resultSet.getString("first_name"),
                  resultSet.getString("last_name"),
                  resultSet.getString("password"),
                  resultSet.getString("email"));

          if (user != null) {

            //opretter token til User
              Algorithm algorithm = Algorithm.HMAC256("secret");
              String token = JWT.create()
                      .withClaim("userid", user.getId())
                      .sign(algorithm);
                      user.setToken(token);

              return user;

          }

        } else {
          System.out.println("Bruger ikke fundet");
        }

        //SQL exception
      } catch (SQLException eSQL) {
        System.out.println(eSQL.getMessage());
      }
      return user;

    }

  }









