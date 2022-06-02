package com.mycompany.backend.controller;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.mycompany.backend.dto.Board;
import com.mycompany.backend.dto.Member;

import lombok.extern.log4j.Log4j2;

@Log4j2
@RestController
@RequestMapping("/rest")
public class RestControllerTest {
	@GetMapping("/getObject")
	public Board getObject() {
	      log.info("실행");
	      Board board = new Board();
	      board.setBno(1);
	      board.setBtitle("제목");
	      board.setBcontent("내용");
	      board.setMid("user");
	      board.setBdate(new Date());
	      return board;
	}
	
	@GetMapping("/getMap")
	   public Map<String, Object> getMap() {
	      log.info("실행");
	      
	      Map<String, Object> map = new HashMap<>();
	      map.put("name", "홍길동");
	      map.put("age", 25);
	      
	      Board board = new Board();
	      board.setBno(1);
	      board.setBtitle("제목");
	      board.setBcontent("내용");
	      board.setMid("user");
	      board.setBdate(new Date());
	      map.put("board", board);
	      
	      return map;
	   }
	
	@GetMapping("/getArray")
	public String[] getArray() {
		log.info("실행");
		String[] array= {"Java","Spring","Vue"};
		return array;
	}
	
	@GetMapping("/getList")
	public List<String> getList1(){
		log.info("실행");
		List<String> list = new ArrayList<>();
		list.add("RestController");
		list.add("JSON");
		list.add("AJAX");
		return list;
	}
	
	@GetMapping("/getList2")
	public List<Board> getList2(){
		log.info("실행");
		List<Board> list = new ArrayList<>();
		for(int i=1; i<=3; i++) {
			Board board = new Board();
			board.setBno(i);
			board.setBtitle("제목"+i);
			board.setBcontent("내용"+i);
			board.setMid("user");
			board.setBdate(new Date());
			list.add(board);
		}
		return list;
	}
	
	@GetMapping("/useEntity")
	public void getHeader(HttpServletResponse response) throws Exception{
		//응답 헤더 설정
		response.setContentType("application/json; charset-UTF-8");
		response.addHeader("TestHeader", "value");
		
		Cookie cookie = new Cookie("refreshToken","xxxxxx");
		response.addCookie(cookie);
		
		//응답 본문 설정
		PrintWriter pw = response.getWriter();
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("result", "success");
		String json = jsonObject.toString();
		
		pw.println(json);
		
		pw.flush();
		pw.close();
	}
	
	
	@GetMapping("/useResponseEntity")
	public ResponseEntity<String> useResponseEntity(){
		log.info("실행");
		
//		BodyBuilder bodyBuilder = ResponseEntity.ok();
//		ResponseEntity<String> result = bodyBuilder.body("success");
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("name","홍길동");
		jsonObject.put("age",25);
		String json = jsonObject.toString();
		
		String cookieStr = ResponseCookie.from("refreshToken", "xxx")
			.build()
			.toString();
		
		return ResponseEntity
				.ok()
				.header(HttpHeaders.CONTENT_TYPE, "application/json")
				.header("TestHeader", "value")
				.header(HttpHeaders.COOKIE,cookieStr)
				.body(json);
		
	}
	
	@RequestMapping("/sendQueryString")
	public Member sendQueryString(Member member) {
		log.info("실행");
		return member;
	}
	
	@PostMapping("/sendJson")
	public Member sendJson(@RequestBody Member member) {
		log.info("실행");
		return member;
	}
	
	@PostMapping("/sendMultipartFormData")
	public Map<String, String> sendMultipartFormData(String title, MultipartFile attach) throws IOException{
		log.info("실행");
		String savedFile = new Date().getTime() + "-" + attach.getOriginalFilename();
		attach.transferTo(new File("C:/Temp/uploadfiles/"+ savedFile));
		
		Map<String, String> map = new HashMap<>();
		map.put("success","success");
		map.put("savedFile",savedFile);
		return map;
	}
}
