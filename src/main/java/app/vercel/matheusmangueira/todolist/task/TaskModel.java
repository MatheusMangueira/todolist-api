package app.vercel.matheusmangueira.todolist.task;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity(name = "tb_tasks")
public class TaskModel {

   @Id
   @GeneratedValue(generator = "UUID")
   private UUID id;
   private String description;

   @Column(length = 50)
   private String title;
   private LocalDateTime startAt;
   private LocalDateTime endAt;
   private String priority;

   private UUID userId;

   @CreationTimestamp
   private LocalDate createdAt;

   public void setTitle(String title) throws Exception {
      if (title.length() > 50) {
         throw new Exception("Title is too long");
      }
      this.title = title;
   }

}
