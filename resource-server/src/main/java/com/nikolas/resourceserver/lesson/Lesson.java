package com.nikolas.resourceserver.lesson;

import java.time.LocalDateTime;

public class Lesson {

    private String title;
    private String description;
    private String instructor;
    private LocalDateTime schedule;

    public Lesson(String title, String description, String instructor, LocalDateTime schedule) {
        this.title = title;
        this.description = description;
        this.instructor = instructor;
        this.schedule = schedule;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getInstructor() {
        return instructor;
    }

    public void setInstructor(String instructor) {
        this.instructor = instructor;
    }

    public LocalDateTime getSchedule() {
        return schedule;
    }

    public void setSchedule(LocalDateTime schedule) {
        this.schedule = schedule;
    }

    @Override
    public String toString() {
        return "Lesson{" +
                "title='" + title + '\'' +
                ", description='" + description + '\'' +
                ", instructor='" + instructor + '\'' +
                ", schedule=" + schedule +
                '}';
    }
}
