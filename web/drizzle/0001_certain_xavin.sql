CREATE TABLE `usage_history` (
	`minute_ms` integer PRIMARY KEY NOT NULL,
	`observed_ms` integer NOT NULL,
	`payload` text NOT NULL
);
