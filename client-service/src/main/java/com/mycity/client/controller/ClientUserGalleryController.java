package com.mycity.client.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;

import com.mycity.client.config.CookieTokenExtractor;
import com.mycity.shared.placedto.UserGalleryDTO;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/client/user")
public class ClientUserGalleryController 
{	
	@Autowired
	private  WebClient.Builder webClientBuilder;
	
	@Autowired
	private CookieTokenExtractor extractor;
	
	private static final String API_GATEWAY_SERVICE_NAME="API-GATEWAY";
	private static final String PATH_TO_ADD_IMAGES_TO_GALLERY="/user/gallery/upload";
	private static final String PATH_TO_GET_IMAGES="/user/gallery/getimages/{districtName}";
	private static final String PATH_TO_DELETE_IMAGE="/user/gallery/deleteimage/{imageId}";
	
	@PostMapping(value = "/gallery/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public Mono<ResponseEntity<String>> uploadImageToGallery(@RequestPart("image") List<MultipartFile> images,
	                                                         @ModelAttribute UserGalleryDTO dto,
	                                                         @RequestHeader(value=HttpHeaders.COOKIE,required = false) String cookie) {
		String token=extractor.extractTokenFromCookie(cookie);
		if (token == null || token.isBlank()) {
		    return Mono.just(ResponseEntity
		            .status(HttpStatus.UNAUTHORIZED)
		            .body("Unauthorized: Missing or empty token in cookie"));
		}

	    return Mono.fromCallable(() -> {
	        MultipartBodyBuilder builder = new MultipartBodyBuilder();

	        // Add image parts
	        for (MultipartFile image : images) {
	            builder.part("images", new ByteArrayResource(image.getBytes()) {
	                @Override
	                public String getFilename() {
	                    return image.getOriginalFilename();
	                }
	            }).contentType(MediaType.parseMediaType(image.getContentType()));
	        }

	        // Add DTO part as JSON
	        builder.part("dto", dto).contentType(MediaType.APPLICATION_JSON);

	        // Send request to PLACE-SERVICE
	        String response = webClientBuilder.build()
	                .post()
	                .uri("lb://" + API_GATEWAY_SERVICE_NAME + PATH_TO_ADD_IMAGES_TO_GALLERY)
	                .contentType(MediaType.MULTIPART_FORM_DATA)
	                .bodyValue(builder.build())
	                .header(HttpHeaders.AUTHORIZATION,"Bearer "+token)
	                .retrieve()
	                .bodyToMono(String.class)
	                .block();

	        return ResponseEntity.ok(response);
	    });
	}
	
	@GetMapping("/gallery/getimages/{districtName}")
	public Mono<ResponseEntity<List<String>>> getImages(@PathVariable String districtName,
			@RequestHeader(value=HttpHeaders.COOKIE,required = false) String cookie) {
		
		String token=extractor.extractTokenFromCookie(cookie);
		if (token == null || token.isBlank()) {
		    return Mono.just(ResponseEntity
		            .status(HttpStatus.UNAUTHORIZED)
		            .body(List.of("Unauthorized: Missing or empty token in cookie")));
		}

	    return webClientBuilder
	            .build()
	            .get()
	            .uri("lb://" + API_GATEWAY_SERVICE_NAME + PATH_TO_GET_IMAGES, districtName)
	            .header(HttpHeaders.AUTHORIZATION,"Bearer "+token)
	            .retrieve()
	            .bodyToMono(new ParameterizedTypeReference<List<String>>() {})
	            .map(urls -> ResponseEntity.ok().body(urls))
	            .onErrorResume(e -> {
	                e.printStackTrace();
	                return Mono.just(ResponseEntity.status(500).body(List.of()));
	            });
	}
 
	@DeleteMapping("/gallery/deleteimage/{imageId}")
	public Mono<ResponseEntity<String>> deleteImage(
	        @PathVariable Long imageId,
	        @RequestHeader(value = HttpHeaders.COOKIE, required = false) String cookie) {

	    String token = extractor.extractTokenFromCookie(cookie);

	    if (token == null || token.isEmpty()) {
	        return Mono.just(ResponseEntity
	                .status(HttpStatus.UNAUTHORIZED)
	                .body("Authorization token missing in cookie"));
	    }

	    return webClientBuilder
	            .build()
	            .delete()
	            .uri("lb://" + API_GATEWAY_SERVICE_NAME + PATH_TO_DELETE_IMAGE, imageId)
	            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
	            .retrieve()
 	            .bodyToMono(String.class)
	            .map(ResponseEntity::ok)
	            .onErrorResume(e -> Mono.just(ResponseEntity
	                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
	                    .body("Error deleting image: " + e.getMessage())));
	}

}
