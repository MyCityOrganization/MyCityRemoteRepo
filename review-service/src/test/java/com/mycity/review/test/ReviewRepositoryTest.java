package com.mycity.review.test;

import com.mycity.review.entity.Review;
import com.mycity.review.repository.ReviewRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
public class ReviewRepositoryTest {

    @Autowired
    private ReviewRepository reviewRepository;

    private Review review1;
    private Review review2;
    private Review review3;

    @BeforeEach
    public void setUp() {
        review1 = new Review();
        review1.setUserName("user1");
        review1.setPlaceName("Beach");
        review1.setReviewDescription("Nice view");
        review1.setUserId(101L);
        review1.setPlaceId(501L);
        review1.setPostedOn(LocalDate.now());

        review2 = new Review();
        review2.setUserName("user2");
        review2.setPlaceName("Beach");
        review2.setReviewDescription("Crowded but good");
        review2.setUserId(102L);
        review2.setPlaceId(501L);
        review2.setPostedOn(LocalDate.now());

        review3 = new Review();
        review3.setUserName("user3");
        review3.setPlaceName("Museum");
        review3.setReviewDescription("Educational");
        review3.setUserId(103L);
        review3.setPlaceId(502L);
        review3.setPostedOn(LocalDate.now());

        reviewRepository.save(review1);
        reviewRepository.save(review2);
        reviewRepository.save(review3);
    }

    @Test
    public void testFindByPlaceId() {
        List<Review> reviews = reviewRepository.findByPlaceId(501L);
        assertEquals(2, reviews.size());
        assertTrue(reviews.stream().anyMatch(r -> r.getUserName().equals("user1")));
        assertTrue(reviews.stream().anyMatch(r -> r.getUserName().equals("user2")));
    }

    @Test
    public void testSaveReview() {
        Review newReview = new Review();
        newReview.setUserName("user4");
        newReview.setPlaceName("Park");
        newReview.setReviewDescription("Very green");
        newReview.setUserId(104L);
        newReview.setPlaceId(503L);
        newReview.setPostedOn(LocalDate.now());

        Review saved = reviewRepository.save(newReview);

        assertNotNull(saved);
        assertNotNull(saved.getReviewId());
        assertEquals("user4", saved.getUserName());
        assertEquals("Park", saved.getPlaceName());
    }
}

