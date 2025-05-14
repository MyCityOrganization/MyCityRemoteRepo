package com.mycity.media.service.test;


import com.mycity.media.entity.EventSubImages;
import com.mycity.media.helper.CloudinaryHelper;
import com.mycity.media.repository.EventSubImagesRepository;
import com.mycity.media.serviceImpl.EventImageServiceImpl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EventImageServiceImplTest {

    @InjectMocks
    private EventImageServiceImpl eventImageService;

    @Mock
    private CloudinaryHelper cloudinaryHelper;

    @Mock
    private EventSubImagesRepository eventSubImagesRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // Test uploading images
    @Test
    void testUploadImages() {
        List<MultipartFile> files = mockMultipartFiles(2);
        List<String> names = Arrays.asList("img1", "img2");
        List<String> imageUrls = Arrays.asList("url1", "url2");

        when(cloudinaryHelper.saveImages(files)).thenReturn(imageUrls);

        eventImageService.uploadImages(files, names, 1L, "EventName");

        verify(cloudinaryHelper).saveImages(files);
        verify(eventSubImagesRepository).save(any(EventSubImages.class));
    }

    // Test updating images
    @Test
    void testUpdateEventImages() {
        List<MultipartFile> files = mockMultipartFiles(1);
        List<String> names = Collections.singletonList("newImage");
        List<String> urls = Collections.singletonList("newUrl");

        when(eventSubImagesRepository.findAllByEventId(1L)).thenReturn(Arrays.asList(new EventSubImages()));
        when(cloudinaryHelper.saveImages(files)).thenReturn(urls);

        String result = eventImageService.updateEventImages(1L, "New Event", files, names);

        verify(eventSubImagesRepository).deleteAll(anyList());
        verify(cloudinaryHelper).saveImages(files);
        verify(eventSubImagesRepository).save(any(EventSubImages.class));

        assertEquals("Images updated successfully for event: New Event", result);
    }

    // Test delete images
    @Test
    void testDeleteAssociatedImages() {
        List<EventSubImages> existing = Arrays.asList(new EventSubImages());

        when(eventSubImagesRepository.findAllByEventId(1L)).thenReturn(existing);

        eventImageService.deleteAssociatedImages(1L);

        verify(eventSubImagesRepository).deleteAll(existing);
    }

    // Test get event images
    @Test
    void testGetEventImages() {
        List<EventSubImages> expected = Arrays.asList(new EventSubImages());

        when(eventSubImagesRepository.findImageUrlsByEventId(1L)).thenReturn(expected);

        List result = eventImageService.getEventImages(1L);

        assertEquals(expected, result);
    }

    // Helper method to mock multipart files
    private List<MultipartFile> mockMultipartFiles(int count) {
        MultipartFile[] files = new MultipartFile[count];
        for (int i = 0; i < count; i++) {
            files[i] = mock(MultipartFile.class);
        }
        return Arrays.asList(files);
    }
}
