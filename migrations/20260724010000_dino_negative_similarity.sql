-- cosine of the closest negative reference at observation time, NULL while
-- no negatives exist; calibrates dino.negative_margin
ALTER TABLE `dino_observations` ADD COLUMN `best_negative_similarity` REAL;
