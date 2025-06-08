package org.jenkinsci.plugins.ansible_tower.exceptions;

/*
    Just our own type of exception
 */

public class AnsibleTowerException extends Exception {
    public AnsibleTowerException(String message) {
        super(message);
    }

    /**
     * Constructor added to include the cause of the exception for better debugging.
     * @param message The detail message.
     * @param cause The cause (which is saved for later retrieval by the getCause() method).
     */
    public AnsibleTowerException(String message, Throwable cause) {
        super(message, cause);
    }
}