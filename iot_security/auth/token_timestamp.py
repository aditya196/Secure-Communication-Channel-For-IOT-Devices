import datetime as dt

def generate_adjusted_timestamp():
	current_datetime = dt.datetime.now(dt.timezone.utc)
	# print("Current datetime: " + current_datetime.isoformat())
	# print("Current timestamp: %d" % int(current_datetime.timestamp()))
	seconds_elapsed_in_current_datetime = current_datetime.second
	# print("Seconds elapsed in current datetime: %d" % current_datetime.second)

	if (seconds_elapsed_in_current_datetime <= 30):
		# print("Less than Equal to 30")
		timestamp1 = adjust_seconds_to_zero(current_datetime, seconds_elapsed_in_current_datetime)
		timestamp2 = adjust_seconds_to_rollover_thirty(current_datetime, seconds_elapsed_in_current_datetime)

		return timestamp1, timestamp2
	else:
		# print("Greater than 30")
		timestamp1 = adjust_seconds_to_zero(current_datetime, seconds_elapsed_in_current_datetime)
		timestamp2 = adjust_seconds_to_thirty(current_datetime, seconds_elapsed_in_current_datetime)

		return timestamp1, timestamp2


def adjust_seconds_to_zero(current_datetime, seconds_elapsed_in_current_datetime):
	adjusted_datetime = current_datetime - dt.timedelta(seconds=seconds_elapsed_in_current_datetime)
	return int(adjusted_datetime.timestamp())

def adjust_seconds_to_thirty(current_datetime, seconds_elapsed_in_current_datetime):
	seconds_to_subtract = seconds_elapsed_in_current_datetime - 30
	adjusted_datetime = current_datetime - dt.timedelta(seconds=seconds_to_subtract)
	return int(adjusted_datetime.timestamp())

def adjust_seconds_to_rollover_thirty(current_datetime, seconds_elapsed_in_current_datetime):
	seconds_to_subtract = 30 + seconds_elapsed_in_current_datetime
	adjusted_datetime = current_datetime - dt.timedelta(seconds=seconds_to_subtract)
	return int(adjusted_datetime.timestamp())