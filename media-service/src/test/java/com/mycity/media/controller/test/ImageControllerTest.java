package com.mycity.media.controller.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mycity.media.controller.ImageController;
import com.mycity.media.service.ImageService;
import com.mycity.shared.mediadto.AboutPlaceImageDTO;
import com.mycity.shared.mediadto.ImageDTO;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.servlet.MockMvc;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ImageController.class)
class ImageControllerTest {

    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private ImageService imageService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser
    void testUploadImageForPlaces() throws Exception {
        MockMultipartFile file = new MockMultipartFile("image", "test.jpg", "image/jpeg", "image data".getBytes());

        Mockito.doNothing().when(imageService)
                .uploadImageForPlaces(any(), eq(1L), eq("PlaceName"), eq("Category"), eq("ImageName"));

        mockMvc.perform(multipart("/media/upload/places")
                        .file(file)
                        .param("placeId", "1")
                        .param("placeName", "PlaceName")
                        .param("category", "Category")
                        .param("imageName", "ImageName")
                        .with(csrf())
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andExpect(status().isOk())
                .andExpect(content().string("Image uploaded successfully"));
    }

    @Test
    @WithMockUser
    void testGetImage() throws Exception {
        ImageDTO imageDTO = new ImageDTO();
        imageDTO.setPlaceId(1L);
        imageDTO.setImageUrl("http://example.com/image.jpg");

        Mockito.when(imageService.fetchImage(1L)).thenReturn(imageDTO);

        mockMvc.perform(get("/media/fetch/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.imageUrl").value("http://example.com/image.jpg"));
    }

//    @Test
//    @WithMockUser
//    void testGetCoverImageForCategory() throws Exception {
//        Mockito.when(imageService.getFirstImageUrlByCategory("Nature"))
//                .thenReturn(Mono.just("http://example.com/cover.jpg"));
//
//        mockMvc.perform(get("/media/bycategory/image")
//                        .param("category", "Nature"))
//                .andExpect(status().isOk())
//                .andExpect(content().string("http://example.com/cover.jpg"));
//    }

    @Test
    @WithMockUser
    void testGetAboutPlaceImagesById() throws Exception {
        List<AboutPlaceImageDTO> images = List.of(new AboutPlaceImageDTO(), new AboutPlaceImageDTO());

        Mockito.when(imageService.getAboutPlaceImages(1L)).thenReturn(images);

        mockMvc.perform(get("/media/images/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    @WithMockUser
    void testGetAboutPlaceImagesByPlaceName() throws Exception {
        List<AboutPlaceImageDTO> images = List.of(new AboutPlaceImageDTO());

        Mockito.when(imageService.getAboutPlaceImages("Paris")).thenReturn(images);

        mockMvc.perform(get("/media/image-byplacename/Paris"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    @WithMockUser
    void testDeleteImage() throws Exception {
        Mockito.when(imageService.deleteImage(1L)).thenReturn("Deleted");

        mockMvc.perform(delete("/media/images/delete/1")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Deleted"));
    }
}
