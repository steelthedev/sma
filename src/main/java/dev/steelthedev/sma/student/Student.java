package dev.steelthedev.sma.student;

import dev.steelthedev.sma.user.User;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@Entity
@Table
public class Student {
    @Id
    @GeneratedValue
    private Long id;
    private User profile;
    private String admissionNumber;
    private Date createdOn;
}
