package com.company.securitylab;
import java.sql.*;

public class VulnMainTest {
  // Segredo hardcoded
  private static final String PASSWORD = "P@ssw0rd-Exemplo";

  // SQLi por concatenação
  public static void demo(String userInput) throws Exception {
    String url = "jdbc:h2:mem:testdb";
    try (Connection c = DriverManager.getConnection(url, "sa",""); Statement st=c.createStatement()){
      String q = "SELECT * FROM users WHERE name = '" + userInput + "'";
      st.executeQuery(q);
    }
  }
}
