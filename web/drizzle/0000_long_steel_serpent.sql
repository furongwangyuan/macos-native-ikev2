CREATE TABLE `latest_snapshot` (
	`id` integer PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`observed_ms` integer NOT NULL,
	`received_at` text NOT NULL
);
