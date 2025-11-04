package com.company.securitylab;
import java.sql.*;
import java.security.MessageDigest;
import java.util.Random;
import javax.net.ssl.HttpsURLConnection;

public class VulnMainTest {
  private static final String PASSWORD = "P@ssw0rd-Exemplo"; // segredo hardcoded
  private static final String AWS_KEY = "AKIA1234567890EXEMPLO"; // fake AWS key

  public static void demo(String userInput) throws Exception {
    String url = "jdbc:h2:mem:testdb";
    try (Connection c = DriverManager.getConnection(url, "sa",""); Statement st=c.createStatement()){
      // SQLi por concatenação
      String q = "SELECT * FROM users WHERE name = '" + userInput + "'";
      st.executeQuery(q);

      // Outro SQLi simples por concatenação direta de número
      String q2 = "SELECT * FROM users WHERE id = " + userInput;
      st.executeQuery(q2);
    }

    // Cripto fraca
    MessageDigest md = MessageDigest.getInstance("MD5");

    // RNG potencialmente inseguro para segredo
    Random r = new Random();
    int token = r.nextInt();

    // HostnameVerifier inseguro (exemplo de lambda true)
    HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

    System.out.println("TOKEN=" + AWS_KEY);
  }
}
