package com.mycity.weather.serviceImpl;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.mycity.shared.tripplannerdto.CoordinateDTO;
import com.mycity.shared.weatherdto.WeatherDTO;
import com.mycity.weather.service.WeatherServiceInterface; 


@Service
public class WeatherService implements WeatherServiceInterface{
	
	@Value("${weather.api.key}")
    private String apiKey;

	public WeatherDTO getWeatherByCoordinates(CoordinateDTO coordinate) {
	    String url = String.format(
	        "https://api.openweathermap.org/data/2.5/weather?lat=%f&lon=%f&units=metric&appid=%s",
	        coordinate.getLatitude(), coordinate.getLongitude(), apiKey
	    );

	    RestTemplate restTemplate = new RestTemplate();
	    ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);

	    JSONObject json = new JSONObject(response.getBody());

	    String location = json.getString("name");

	    JSONObject weatherJson = json.getJSONArray("weather").getJSONObject(0);
	    String condition = weatherJson.getString("main");         // e.g., "Clear", "Rain"
	    String description = weatherJson.getString("description"); // e.g., "clear sky", "light rain"

	    double temp = json.getJSONObject("main").getDouble("temp");

	    return new WeatherDTO(location, condition, description, temp);
	}

	public RestTemplate createRestTemplate() {
	    return new RestTemplate();
	}


}
