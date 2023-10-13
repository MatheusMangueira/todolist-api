package app.vercel.matheusmangueira.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import app.vercel.matheusmangueira.todolist.user.IUserRepository;
import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaksAuth extends OncePerRequestFilter {

   @Autowired
   private IUserRepository userRepository;

   @Override
   protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
         throws ServletException, IOException {

      var serveletPath = request.getServletPath();
      if (serveletPath.startsWith("/tasks/")) {

         // pegando o header
         var authorization = request.getHeader("Authorization");
         // retirando o Basic e o espaço
         var authEncoded = authorization.substring("Basic".length()).trim();
         // decodificando o base64
         byte[] authDecode = Base64.getDecoder().decode(authEncoded);
         // transformando em String
         var authString = new String(authDecode);
         // separando o username e password
         String[] credentials = authString.split(":");
         // pegando o username e password
         String username = credentials[0];
         String password = credentials[1];

         // validando usuario
         var user = this.userRepository.findByUsername(username);

         if (user == null) {
            response.sendError(401, "User not found");
            return;
         } else {
            // validando senha
            var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

            if (passwordVerify.verified) {
               request.setAttribute("userId", user.getId());
               filterChain.doFilter(request, response);
            } else {
               response.sendError(401);
            }

         }

      } else {
         filterChain.doFilter(request, response);
      }

   }

}
