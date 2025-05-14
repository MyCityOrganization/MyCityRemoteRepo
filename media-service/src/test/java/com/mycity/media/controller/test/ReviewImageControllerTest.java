package com.mycity.media.controller.test;

import com.mycity.media.controller.ReviewImageController;
import com.mycity.media.service.ReviewImageService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ReviewImageController.class)
class ReviewImageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ReviewImageService reviewImageService;

    @Test
    @WithMockUser
    void testAddImageToReview() throws Exception {
        MockMultipartFile file = new MockMultipartFile("image", "test.jpg", "image/jpeg", "image-data".getBytes());

        Mockito.doNothing().when(reviewImageService).uploadReviewImage(any(), eq(101L), eq(202L), eq("PlaceName"), eq(303L), eq("UserName"));

        mockMvc.perform(multipart("/media/review/upload")
                        .file(file)
                        .param("reviewId", "101")
                        .param("placeId", "202")
                        .param("placeName", "PlaceName")
                        .param("userId", "303")
                        .param("userName", "UserName")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Images Uploaded Successfully."));
    }

    @Test
    @WithMockUser
    void testDeleteImage() throws Exception {
        Mockito.when(reviewImageService.deleteReviewImage(101L)).thenReturn("Deleted");

        mockMvc.perform(delete("/media/review/delete/101")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Deleted"));
    }

    @Test
    @WithMockUser
    void testGetImagesPlaceReview() throws Exception {
        Mockito.when(reviewImageService.getReviewForPlace(202L)).thenReturn("http://images.com/review123.jpg");

        mockMvc.perform(get("/media/review/image/place/202"))
                .andExpect(status().isOk())
                .andExpect(content().string("http://images.com/review123.jpg"));
    }
}
