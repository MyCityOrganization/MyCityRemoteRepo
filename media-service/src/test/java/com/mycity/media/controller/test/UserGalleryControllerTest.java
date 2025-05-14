package com.mycity.media.controller.test;

import com.mycity.media.controller.UserGalleryController;
import com.mycity.media.service.UserGalleryService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.NoSuchElementException;

import static org.mockito.ArgumentMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserGalleryController.class)
class UserGalleryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserGalleryService service;

    @Test
    @WithMockUser
    void testUploadImageToGallery() throws Exception {
        MockMultipartFile file = new MockMultipartFile("image", "test.jpg", "image/jpeg", "image-data".getBytes());

        Mockito.when(service.uploadImages(any(), eq(1L), eq(2L), eq("PlaceName"),
                eq("City"), eq("District"), eq("State"))).thenReturn("Upload successful");

        mockMvc.perform(multipart("/media/gallery/upload")
                        .file(file)
                        .param("userId", "1")
                        .param("placeId", "2")
                        .param("placeName", "PlaceName")
                        .param("city", "City")
                        .param("district", "District")
                        .param("state", "State")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Upload successful"));
    }

    @Test
    @WithMockUser
    void testUploadImageToGallery_EmptyFile() throws Exception {
        MockMultipartFile file = new MockMultipartFile("image", "", "image/jpeg", new byte[0]);

        mockMvc.perform(multipart("/media/gallery/upload")
                        .file(file)
                        .param("userId", "1")
                        .param("placeId", "2")
                        .param("placeName", "PlaceName")
                        .param("city", "City")
                        .param("district", "District")
                        .param("state", "State")
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Image file is missing or empty."));
    }

    @Test
    @WithMockUser
    void testGetAllImages() throws Exception {
        List<String> imageUrls = List.of("http://img1.jpg", "http://img2.jpg");
        Mockito.when(service.getImages("District")).thenReturn(imageUrls);

        mockMvc.perform(get("/media/gallery/getimages/District"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    @WithMockUser
    void testGetAllImages_NoContent() throws Exception {
        Mockito.when(service.getImages("District")).thenReturn(List.of());

        mockMvc.perform(get("/media/gallery/getimages/District"))
                .andExpect(status().isNoContent());
    }

    @Test
    @WithMockUser
    void testDeleteImage_Success() throws Exception {
        Mockito.when(service.deleteImage(100L)).thenReturn("Deleted successfully");

        mockMvc.perform(delete("/media/gallery/deleteimage/100")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Deleted successfully"));
    }

    @Test
    @WithMockUser
    void testDeleteImage_NotFound() throws Exception {
        Mockito.when(service.deleteImage(100L)).thenThrow(new NoSuchElementException("Image not found"));

        mockMvc.perform(delete("/media/gallery/deleteimage/100")
                        .with(csrf()))
                .andExpect(status().isNotFound())
                .andExpect(content().string("Image not found"));
    }

    @Test
    @WithMockUser
    void testDeleteImage_BadRequest() throws Exception {
        Mockito.when(service.deleteImage(100L)).thenThrow(new IllegalArgumentException("Invalid image ID"));

        mockMvc.perform(delete("/media/gallery/deleteimage/100")
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid image ID"));
    }
}
