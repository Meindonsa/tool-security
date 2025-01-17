package com.meindonsa.security.exception;


import com.meindonsa.config.exception.CustomExceptionHandler;
import com.meindonsa.config.exception.ErrorResponse;
import com.meindonsa.config.utils.Messages;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

@SuppressWarnings({"unchecked", "rawtypes"})
@ControllerAdvice
public class SecurityExceptionHandler extends CustomExceptionHandler {

    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public final ResponseEntity<Object> handleInvalidAuth(
            InternalAuthenticationServiceException ex, WebRequest request) {
        return new ResponseEntity(
                new ErrorResponse(Messages.ERR_INVALID_DATA, processError(ex)),
                HttpStatus.NOT_ACCEPTABLE);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public final ResponseEntity<Object> accessDenied(AccessDeniedException ex, WebRequest request) {
        return new ResponseEntity(
                new ErrorResponse(Messages.ERR_UNAUTHORIZED, processError(ex)),
                HttpStatus.FORBIDDEN);
    }
}
