package com.mycity.media.controller.test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.mycity.media.controller.UserProfileImageController;
import com.mycity.media.service.UserProfileImgService;

@WebMvcTest(UserProfileImageController.class)
class UserProfileImageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserProfileImgService profileImgService;

    @Test
    @WithMockUser
    void testUploadUserImage() throws Exception {
        MockMultipartFile file = new MockMultipartFile("image", "profile.jpg", "image/jpeg", "fake-image-data".getBytes());

        Mockito.doNothing().when(profileImgService).uploadUserImage(any(), eq("user123"));

        mockMvc.perform(multipart("/media/upload")
                        .file(file)
                        .param("userId", "user123")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("Image uploaded successfully...!!"));
    }

    @Test
    @WithMockUser
    void testGetImageByUserId() throws Exception {
        Mockito.when(profileImgService.getImageUrlByUserId("user123")).thenReturn("http://images.com/user123.jpg");

        mockMvc.perform(get("/media/get-image/user123"))
                .andExpect(status().isOk())
                .andExpect(content().string("http://images.com/user123.jpg"));
    }
}
