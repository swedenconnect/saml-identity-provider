/*
 * Copyright 2023-2024 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.saml.idp.audit.repository;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.apache.commons.io.FilenameUtils;
import org.springframework.util.StringUtils;

/**
 * A wrapper class to Java Util Logging's {@link FileHandler} that supports "rolling files" per date.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
class DateRollingFileHandler extends Handler {

  /** The log file. */
  private final Path logFile;

  /** Holds the last-modified time of the log file. */
  private Instant lastModified = null;

  /** The actual log handler. */
  private FileHandler handler;

  /** Formatter for backup file names. */
  private static final DateTimeFormatter dateFormatter =
      DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneId.of("UTC"));

  /**
   * Constructor setting up the file handler.
   *
   * @param logFile the log file (including the path)
   * @throws IOException for file errors
   */
  public DateRollingFileHandler(final String logFile) throws IOException {
    this.logFile = Path.of(Objects.requireNonNull(logFile, "logFile must not be null"));
    if (Files.exists(this.logFile)) {
      if (Files.isDirectory(this.logFile)) {
        throw new IOException("Given logFile points to a directory and not a file");
      }
      if (!Files.isWritable(this.logFile)) {
        throw new IOException("Given logFile is not writable");
      }
      // Get last modified date ...
      final BasicFileAttributes attr = Files.readAttributes(this.logFile, BasicFileAttributes.class);
      this.lastModified = attr.lastModifiedTime().toInstant();
    }
    else {
      final Path parent = this.logFile.getParent();
      if (parent != null && !Files.exists(parent)) {
        Files.createDirectories(parent);
      }
    }
    this.initializeHandler();
  }

  /**
   * Initializes the underlying handler.
   *
   * @throws IOException if the {@link FileHandler} cannot be created
   */
  private void initializeHandler() throws IOException {
    this.handler = new FileHandler(this.logFile.toString(), true);
    this.handler.setLevel(Level.INFO);
    this.handler.setFormatter(new AuditLoggerFormatter());
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void publish(final LogRecord record) {
    if (record != null && this.isLoggable(record)) {

      // Check if the current log file is too old to write to ...
      //
      if (this.lastModified != null
          && Instant.now().truncatedTo(ChronoUnit.DAYS).isAfter(this.lastModified.truncatedTo(ChronoUnit.DAYS))) {
        // Time to save the current log file to <log-file>-<date>.log
        this.backupFile();
      }

      this.handler.publish(record);
      this.lastModified = Instant.now();
    }
  }

  /**
   * Performs a backup of the current log file to <log-file-name>-<date>.<ext> and re-initializes the underlying
   * handler.
   *
   * @throws UncheckedIOException if the backup operation fails
   */
  private void backupFile() throws UncheckedIOException {
    try {
      this.flush();
      this.close();

      final String dateString = dateFormatter.format(this.lastModified);
      final String path = this.logFile.toString();
      final String extension = FilenameUtils.getExtension(path);
      final String backupPath = StringUtils.hasText(extension)
          ? String.format("%s-%s.%s",
              path.substring(0, path.length() - extension.length() - 1), dateString, extension)
          : String.format("%s-%s", path, dateString);

      Files.move(this.logFile, Path.of(backupPath), StandardCopyOption.REPLACE_EXISTING);
      this.lastModified = null;
      this.initializeHandler();
    }
    catch (final IOException e) {
      throw new UncheckedIOException(e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void flush() {
    this.handler.flush();
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void close() throws SecurityException {
    this.handler.close();
  }

  /**
   * A simple {@link Formatter} that only outputs the actual message.
   */
  private static class AuditLoggerFormatter extends Formatter {

    /** {@inheritDoc} */
    @Override
    public String format(final LogRecord record) {
      return record.getMessage() + System.lineSeparator();
    }

  }
}
