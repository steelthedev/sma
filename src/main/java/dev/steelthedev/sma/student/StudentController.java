package dev.steelthedev.sma.student;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/student")
public class StudentController {
    @GetMapping("/test")
    public ResponseEntity<String> test(){
        return ResponseEntity.ok("Done");
    }
}
