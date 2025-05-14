package com.mycity.media.controller.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mycity.media.controller.EventImageController;
import com.mycity.media.entity.EventSubImages;
import com.mycity.media.service.EventImageService;

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

import static org.mockito.ArgumentMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(EventImageController.class)
class EventImageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private EventImageService imageService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser
    void testUploadImages() throws Exception {
        MockMultipartFile file1 = new MockMultipartFile("files", "img1.jpg", "image/jpeg", "image-data-1".getBytes());
        MockMultipartFile file2 = new MockMultipartFile("files", "img2.jpg", "image/jpeg", "image-data-2".getBytes());

        Mockito.doNothing().when(imageService).uploadImages(anyList(), anyList(), eq(1L), eq("Sample Event"));

        mockMvc.perform(multipart("/media/upload/images")
                        .file(file1)
                        .file(file2)
                        .param("names", "Image1", "Image2")
                        .param("eventId", "1")
                        .param("eventName", "Sample Event")
                        .with(csrf())
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andExpect(status().isOk())
                .andExpect(content().string("Images uploaded successfully"));
    }

    @Test
    @WithMockUser
    void testUpdateEventImages() throws Exception {
        MockMultipartFile file1 = new MockMultipartFile("files", "img1.jpg", "image/jpeg", "image-data-1".getBytes());
        MockMultipartFile file2 = new MockMultipartFile("files", "img2.jpg", "image/jpeg", "image-data-2".getBytes());

        Mockito.when(imageService.updateEventImages(eq(1L), eq("Sample Event"), anyList(), anyList()))
               .thenReturn("Images updated");

        mockMvc.perform(multipart("/media/update/images/1")
                        .file(file1)
                        .file(file2)
                        .param("names", "Image1", "Image2")
                        .param("eventName", "Sample Event")
                        .with(csrf())
                        .with(request -> {
                            request.setMethod("PUT"); // Override POST to PUT for multipart
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(content().string("Images updated"));
    }

    @Test
    @WithMockUser
    void testDeleteEventImages() throws Exception {
        Mockito.doNothing().when(imageService).deleteAssociatedImages(1L);

        mockMvc.perform(delete("/media/delete/images/1")
                        .param("eventName", "Sample Event")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Images for event Sample Event deleted."));
    }

    @Test
    @WithMockUser
    void testGetEventImages() throws Exception {
        EventSubImages eventImage = new EventSubImages();
        eventImage.setImageUrls(List.of("http://img1.jpg", "http://img2.jpg"));

        Mockito.when(imageService.getEventImages(1L)).thenReturn(List.of(eventImage));

        mockMvc.perform(get("/media/fetch/images/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0]").value("http://img1.jpg"))
                .andExpect(jsonPath("$[1]").value("http://img2.jpg"));
    }
}
